//! Server-rendered pages of the operator console. No page contains a script or
//! an inline style: every dynamic value is escaped here, and the meters and the
//! chart are SVG attributes, which the content security policy allows.
use std::iter;

use chrono::{DateTime, Datelike, Duration, Utc, Weekday};
use qrcode::{Color, EcLevel, QrCode};

use crate::admin::model::{
    AdminContext, AuditPage, CompanyPage, CompanyRow, DayTotal, Money, OverviewPage, SecurityPage,
    SetupKind, SetupPage, TenantPage, TotpEnrollment, Usage,
};
use crate::admin::service::AdminService;
use crate::managed::client_model::{ClientKeyState, CreatedKey, ManagedClient, ManagedClientKey};

pub const PUBLIC_HOST: &str = "ai.jhonacode.com";

pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// A URL path segment: everything but unreserved characters is percent-encoded.
pub fn segment(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn money(micros: i64) -> String {
    Money(micros).to_string()
}

fn date(value: DateTime<Utc>) -> String {
    value.format("%b %-d, %Y").to_string()
}

fn stamp(value: DateTime<Utc>) -> String {
    value.format("%b %-d %H:%M:%S").to_string()
}

fn ago(now: DateTime<Utc>, then: DateTime<Utc>) -> String {
    let seconds = (now - then).num_seconds().max(0);
    match seconds {
        0..=59 => format!("{seconds} s ago"),
        60..=3599 => format!("{} min ago", seconds / 60),
        3600..=86_399 => format!("{} h ago", seconds / 3600),
        _ => date(then),
    }
}

fn hidden(name: &str, value: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
        escape(value)
    )
}

fn pill(class: &str, text: &str) -> String {
    format!("<span class=\"pill {class}\">{}</span>", escape(text))
}

fn code_field(id: &str) -> String {
    format!(
        "<label for=\"{id}\">Authenticator code<input class=\"code-input\" type=\"text\" id=\"{id}\" name=\"code\" inputmode=\"numeric\" pattern=\"[0-9 ]{{6,7}}\" autocomplete=\"one-time-code\" required></label>"
    )
}

fn step_up(id: &str, note: &str) -> String {
    format!(
        "<div class=\"step-up\">{}<p>{}</p></div>",
        code_field(id),
        escape(note)
    )
}

/// A QR code drawn with SVG rectangles, one path per dark run. Black on white
/// in both themes, with the 4-module quiet zone scanners expect.
fn qr(text: &str) -> String {
    const QUIET: usize = 4;
    let Ok(code) = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M) else {
        return String::new();
    };
    let width = code.width();
    let size = width + QUIET * 2;
    let mut path = String::new();
    for (y, row) in code.to_colors().chunks(width).enumerate() {
        let mut run = None;
        for (x, color) in row.iter().chain(iter::once(&Color::Light)).enumerate() {
            match (color, run) {
                (Color::Dark, None) => run = Some(x),
                (Color::Light, Some(start)) => {
                    let length = x - start;
                    path.push_str(&format!(
                        "M{} {}h{length}v1h-{length}z",
                        start + QUIET,
                        y + QUIET
                    ));
                    run = None;
                }
                _ => {}
            }
        }
    }
    format!(
        "<svg class=\"qr\" viewBox=\"0 0 {size} {size}\" role=\"img\" aria-label=\"QR code for your authenticator app\" shape-rendering=\"crispEdges\"><rect class=\"qr-light\" width=\"{size}\" height=\"{size}\"></rect><path class=\"qr-dark\" d=\"{path}\"></path></svg>"
    )
}

/// The QR code and, for apps that cannot scan, the key to type.
fn authenticator(uri: &str, secret: &str) -> String {
    format!(
        "<div class=\"totp-setup\">{}<div><p>Scan the QR code with Google Authenticator, Microsoft Authenticator, 1Password or a similar app. If you cannot scan it, type this key:</p><div class=\"secret\">{}</div></div></div>",
        qr(uri),
        escape(secret)
    )
}

fn meter(usage: &Usage, label: &str) -> String {
    let spent = Usage::share(usage.spent, usage.limit);
    let held = Usage::share(usage.held, usage.limit).min(100.0 - spent);
    format!(
        "<svg class=\"meter\" viewBox=\"0 0 100 10\" preserveAspectRatio=\"none\" role=\"img\" aria-label=\"{}\"><rect class=\"m-avail\" width=\"100\" height=\"10\"></rect><rect class=\"m-spent\" width=\"{spent:.2}\" height=\"10\"></rect><rect class=\"m-held\" x=\"{spent:.2}\" width=\"{held:.2}\" height=\"10\"></rect></svg>",
        escape(label)
    )
}

fn usage_label(usage: &Usage) -> String {
    match (usage.limit, usage.available()) {
        (Some(limit), Some(available)) => format!(
            "{} spent · {} held · {} available of {}",
            money(usage.spent),
            money(usage.held),
            money(available),
            money(limit)
        ),
        _ => format!(
            "{} spent · {} held · no cap",
            money(usage.spent),
            money(usage.held)
        ),
    }
}

fn legend_ledger() -> &'static str {
    "<div class=\"legend\" aria-hidden=\"true\"><span><i class=\"spent\"></i>Spent</span><span><i class=\"held\"></i>Held</span><span><i class=\"avail\"></i>Available</span></div>"
}

pub struct Notice {
    pub class: &'static str,
    pub text: &'static str,
}

/// Fixed messages chosen by code, so nothing a URL carries is ever reflected.
pub fn notice(notice: Option<&str>, error: Option<&str>) -> Option<Notice> {
    let from_error = error.and_then(|code| {
        let text = match code {
            "code" => "The authenticator code is wrong or was already used. Wait for the next code and try again.",
            "invalid" => "Some values are not valid. Check the format of each field and try again.",
            "conflict" => "The change conflicts with the current state: a slug or workspace already in use, a cap below the tenant ceilings, or a key that changed.",
            "budget" => "The budget cannot cover that amount.",
            "forbidden" => "The current policy does not allow that change.",
            "not_found" => "That item no longer exists.",
            "unavailable" => "The service could not complete the request. Try again in a moment.",
            _ => return None,
        };
        Some(Notice { class: "danger", text })
    });
    from_error.or_else(|| {
        notice.and_then(|code| {
            let text = match code {
                "welcome" => "Your access is ready. Keep the authenticator app: it is needed for every sign-in and every change.",
                "company_created" => "Company created. Create its first API key.",
                "company_updated" => "Company settings saved.",
                "workspace_added" => "Workspace assigned.",
                "workspace_removed" => "Workspace removed.",
                "key_revoked" => "API key revoked. Calls with it are refused from now on.",
                "company_suspended" => {
                    "Company suspended. Its live OpenRouter keys are being revoked."
                }
                "company_reactivated" => "Company reactivated. Create new API keys for it.",
                "recovery_authorized" => {
                    "Recovery authorized. The subject can request a new key now."
                }
                "password_changed" => "Password changed. Your other sessions were signed out.",
                "authenticator_replaced" => "Authenticator replaced. Use the new app from now on.",
                "session_revoked" => "Session signed out.",
                "sessions_revoked" => "Other sessions signed out.",
                _ => return None,
            };
            Some(Notice { class: "ok", text })
        })
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Overview,
    Companies,
    Audit,
    Security,
}

fn document(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{} · asystant</title><link rel=\"stylesheet\" href=\"/admin/style.css\"></head><body>{body}</body></html>",
        escape(title)
    )
}

fn layout(
    ctx: &AdminContext,
    section: Section,
    title: &str,
    notice: Option<Notice>,
    content: &str,
) -> String {
    let nav = [
        (Section::Overview, "/admin", "Overview"),
        (Section::Companies, "/admin/companies", "Companies"),
        (Section::Audit, "/admin/audit", "Audit log"),
        (Section::Security, "/admin/security", "Security"),
    ]
    .iter()
    .map(|(item, href, label)| {
        let current = if *item == section {
            " aria-current=\"page\""
        } else {
            ""
        };
        format!("<li><a href=\"{href}\"{current}>{label}</a></li>")
    })
    .collect::<String>();
    let idle = ctx.session.last_seen_at + Duration::minutes(AdminService::SESSION_IDLE_MINUTES);
    let banner = notice
        .map(|notice| {
            format!(
                "<div class=\"notice {}\" role=\"status\">{}</div>",
                notice.class, notice.text
            )
        })
        .unwrap_or_default();
    document(
        title,
        &format!(
            "<div class=\"shell\"><aside class=\"side\" aria-label=\"Administration\"><a class=\"brand\" href=\"/admin\">asystant<span class=\"dot\">·</span>ai<small>{PUBLIC_HOST}</small></a><nav><ul>{nav}</ul></nav><div class=\"signed\"><span>Signed in as <strong>{}</strong></span><span>Session ends {} UTC if idle</span><form method=\"post\" action=\"/admin/logout\">{}<button class=\"button secondary small\">Sign out</button></form></div></aside><main class=\"view\">{banner}{content}<footer class=\"foot\">asystant-api {} · {PUBLIC_HOST} · server-rendered, no scripts, no third-party requests</footer></main></div>",
            escape(&ctx.admin.username),
            idle.format("%H:%M"),
            hidden("csrf", ctx.csrf()),
            env!("CARGO_PKG_VERSION"),
        ),
    )
}

// ---------------------------------------------------------------- sign-in

pub fn login(csrf: &str, error: Option<&str>) -> String {
    let error = match error {
        Some("locked") => {
            "<div class=\"notice danger\" role=\"alert\">Sign-in is locked for 15 minutes after 5 failed attempts.</div>"
        }
        Some(_) => {
            "<div class=\"notice danger\" role=\"alert\">Wrong username, password or code.</div>"
        }
        None => "",
    };
    document(
        "Sign in",
        &format!(
            "<main class=\"auth\"><div class=\"stack\"><span class=\"brand\">asystant<span class=\"dot\">·</span>ai</span><h1>Sign in to the operator console</h1><p class=\"muted\">Companies, API keys and OpenRouter spend for {PUBLIC_HOST}.</p></div>{error}<form class=\"panel stack\" method=\"post\" action=\"/admin/login\">{}<label for=\"login-user\">Username<input type=\"text\" id=\"login-user\" name=\"username\" autocomplete=\"username\" required maxlength=\"64\" autocapitalize=\"none\" spellcheck=\"false\"></label><label for=\"login-password\">Password<input type=\"password\" id=\"login-password\" name=\"password\" autocomplete=\"current-password\" required maxlength=\"256\"></label><label for=\"login-code\">Authenticator code<input class=\"code-input\" type=\"text\" id=\"login-code\" name=\"code\" inputmode=\"numeric\" pattern=\"[0-9 ]{{6,7}}\" autocomplete=\"one-time-code\" required><span class=\"hint\">The 6-digit code from your authenticator app.</span></label><button>Sign in</button></form><p class=\"muted\"><small>Five failed attempts lock sign-in for 15 minutes. Sessions end after 30 minutes idle or 8 hours in total. Every attempt is recorded in the audit log.</small></p></main>",
            hidden("csrf", csrf)
        ),
    )
}

pub fn setup(csrf: &str, token: &str, page: &SetupPage, error: Option<&str>) -> String {
    let error = match error {
        Some("invalid") => {
            "<div class=\"notice danger\" role=\"alert\">Check the username (3 to 64 lowercase letters, digits, dots, hyphens or underscores) and that both passwords match and have at least 12 characters.</div>"
        }
        Some("code") => {
            "<div class=\"notice danger\" role=\"alert\">The authenticator code is wrong. Wait for the next code and try again.</div>"
        }
        Some("locked") => {
            "<div class=\"notice danger\" role=\"alert\">Setup is locked for 15 minutes after 5 failed attempts.</div>"
        }
        Some("expired") => {
            "<div class=\"notice danger\" role=\"alert\">The form expired. Fill it in again.</div>"
        }
        Some(_) => {
            "<div class=\"notice danger\" role=\"alert\">The access could not be saved. Try again in a moment.</div>"
        }
        None => "",
    };
    let (title, button) = match page.kind {
        SetupKind::First => ("Set up the operator console", "Create access"),
        SetupKind::Invitation => ("Set up your access", "Create access"),
        SetupKind::Reset => ("Set new credentials", "Save and sign in"),
    };
    let username = match &page.username {
        Some(username) => format!(
            "<dl class=\"facts\"><dt>Username</dt><dd><strong>{}</strong></dd></dl>",
            escape(username)
        ),
        None => "<label for=\"setup-user\">Username<input type=\"text\" id=\"setup-user\" name=\"username\" autocomplete=\"username\" required minlength=\"3\" maxlength=\"64\" autocapitalize=\"none\" spellcheck=\"false\"><span class=\"hint\">Lowercase letters, digits, dots, hyphens or underscores.</span></label>".to_string(),
    };
    document(
        title,
        &format!(
            "<main class=\"auth wide\"><div class=\"stack\"><span class=\"brand\">asystant<span class=\"dot\">·</span>ai</span><h1>{title}</h1><p class=\"muted\">This link works once, until {} UTC. Choose a password and add the authenticator: you need both to sign in.</p></div>{error}<form class=\"panel stack\" method=\"post\" action=\"/admin/setup\" autocomplete=\"off\">{}{}{username}<label for=\"setup-password\">Password<input type=\"password\" id=\"setup-password\" name=\"password\" autocomplete=\"new-password\" required minlength=\"12\" maxlength=\"256\"><span class=\"hint\">At least 12 characters. A long phrase is best.</span></label><label for=\"setup-password-confirm\">Repeat the password<input type=\"password\" id=\"setup-password-confirm\" name=\"password_confirm\" autocomplete=\"new-password\" required minlength=\"12\" maxlength=\"256\"></label><h2>Authenticator</h2>{}<label for=\"setup-code\">Code shown by the app<input class=\"code-input\" type=\"text\" id=\"setup-code\" name=\"code\" inputmode=\"numeric\" pattern=\"[0-9 ]{{6,7}}\" autocomplete=\"one-time-code\" required></label><button>{button}</button></form><p class=\"muted\"><small>The key is shown only on this page. If you lose the authenticator later, run <code>asystant_api admin reset &lt;username&gt;</code> on the server for a new link.</small></p></main>",
            page.expires_at.format("%b %-d %H:%M"),
            hidden("csrf", csrf),
            hidden("token", token),
            authenticator(&page.uri, &page.secret),
        ),
    )
}

pub fn setup_invalid() -> String {
    document(
        "Link not valid",
        &format!(
            "<main class=\"auth\"><div class=\"stack\"><span class=\"brand\">asystant<span class=\"dot\">·</span>ai</span><h1>This link is not valid</h1><p class=\"muted\">It was already used, it expired, or a newer link replaced it. Get a new one on the server with <code>asystant_api admin reset &lt;username&gt;</code>; while no administrator exists, every start of the service prints one to the logs.</p></div><a class=\"button secondary\" href=\"/admin/login\">Go to sign in</a><p class=\"muted\"><small>{PUBLIC_HOST}</small></p></main>"
        ),
    )
}

// ---------------------------------------------------------------- overview

fn chart(series: &[DayTotal]) -> String {
    let (x0, x1, y0, y1) = (44.0_f64, 628.0_f64, 14.0_f64, 168.0_f64);
    let max = series.iter().map(|day| day.spent).max().unwrap_or(0) as f64 / 1_000_000.0;
    let step = [
        1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1_000.0, 2_000.0, 5_000.0,
    ]
    .into_iter()
    .find(|step| step * 3.0 >= max)
    .unwrap_or(10_000.0);
    let top = step * 3.0;
    let band = (x1 - x0) / series.len().max(1) as f64;
    let mut svg = String::from(
        "<svg class=\"chart\" viewBox=\"0 0 640 196\" role=\"img\" aria-label=\"Daily confirmed spend, last 30 days\">",
    );
    for tick in 0..=3 {
        let value = step * f64::from(tick);
        let y = y1 - value / top * (y1 - y0);
        svg.push_str(&format!(
            "<line class=\"grid\" x1=\"{x0}\" x2=\"{x1}\" y1=\"{y:.1}\" y2=\"{y:.1}\"></line><text class=\"axis-label\" x=\"36\" y=\"{:.1}\" text-anchor=\"end\">${value}</text>",
            y + 4.0
        ));
    }
    let last = series.len().saturating_sub(1);
    for (index, day) in series.iter().enumerate() {
        let usd = day.spent as f64 / 1_000_000.0;
        let height = (usd / top * (y1 - y0)).max(0.0);
        let x = x0 + index as f64 * band + (band - 12.0) / 2.0;
        let class = if index == last {
            "bar today"
        } else if matches!(day.date.weekday(), Weekday::Sat | Weekday::Sun) {
            "bar weekend"
        } else {
            "bar"
        };
        svg.push_str(&format!(
            "<rect class=\"{class}\" x=\"{x:.1}\" y=\"{:.1}\" width=\"12\" height=\"{height:.1}\" rx=\"2\"><title>{}: {}</title></rect>",
            y1 - height,
            day.date.format("%b %d"),
            money(day.spent)
        ));
        if index == 0 || index == last || index % 7 == 0 && index + 3 < last {
            let label = if index == last {
                "Today".to_string()
            } else {
                day.date.format("%b %-d").to_string()
            };
            let anchor = if index == last { "end" } else { "middle" };
            svg.push_str(&format!(
                "<text class=\"axis-label\" x=\"{:.1}\" y=\"188\" text-anchor=\"{anchor}\">{label}</text>",
                x + 6.0
            ));
        }
    }
    svg.push_str("</svg>");
    svg
}

fn lease_pill(status: &str) -> String {
    match status {
        "issued" => pill("ok", "Issued"),
        "reserved" => pill("info", "Reserved"),
        "provisioning" => pill("info", "Creating"),
        "uncertain" => pill("warn", "Uncertain"),
        "revocation_pending" => pill("warn", "Revoking"),
        "revoked" => pill("danger", "Revoked"),
        other => pill("", other),
    }
}

fn worker_row(
    label: &str,
    now: DateTime<Utc>,
    last: Option<DateTime<Utc>>,
    stale_after: i64,
    configured: bool,
) -> String {
    let status = match (configured, last) {
        (false, _) => pill("", "Not configured"),
        (true, None) => pill("info", "Starting"),
        (true, Some(last)) if (now - last).num_seconds() > stale_after => {
            pill("warn", &format!("Last success {}", ago(now, last)))
        }
        (true, Some(last)) => pill("ok", &ago(now, last)),
    };
    format!("<li><span>{label}</span>{status}</li>")
}

pub fn overview(ctx: &AdminContext, page: &OverviewPage, notice: Option<Notice>) -> String {
    let now = page.now;
    let mut html = format!(
        "<div class=\"page-head\"><div class=\"title\"><span class=\"eyebrow\">{} · UTC day</span><h1>Overview</h1></div><div class=\"actions\"><a class=\"button secondary\" href=\"/admin/export.csv\">Export this month (CSV)</a><a class=\"button\" href=\"/admin/companies/new\">New company</a></div></div>",
        now.format("%A, %B %-d, %Y")
    );
    let attention_class = if page.attention.is_empty() {
        "kpi"
    } else {
        "kpi attention"
    };
    html.push_str(&format!(
        "<div class=\"kpis\"><div class=\"kpi\"><span class=\"label\">Spent today</span><span class=\"value\">{}</span><span class=\"sub\">Confirmed by OpenRouter</span></div><div class=\"kpi\"><span class=\"label\">Held by live keys</span><span class=\"value\">{}</span><span class=\"sub\">Reserved until usage is confirmed</span></div><div class=\"kpi\"><span class=\"label\">{} to date</span><span class=\"value\">{}</span><span class=\"sub\">Daily budgets · {} active companies</span></div><div class=\"kpi\"><span class=\"label\">Keys issued today</span><span class=\"value\">{}</span><span class=\"sub\">One per subject and day</span></div><div class=\"{attention_class}\"><span class=\"label\">Needs attention</span><span class=\"value\">{}</span><span class=\"sub\">Uncertain or pending revocation</span></div></div>",
        money(page.spent_today),
        money(page.held_today),
        now.format("%B"),
        money(page.month_to_date),
        page.active_companies,
        page.keys_today,
        page.attention.len(),
    ));
    html.push_str(&format!(
        "<section class=\"panel\"><div class=\"panel-head\"><h2>Confirmed spend, last 30 days</h2><div class=\"legend\" aria-hidden=\"true\"><span><i class=\"spent\"></i>Weekday</span><span><i class=\"weekend\"></i>Weekend</span><span><i class=\"today\"></i>Today, in progress</span></div></div><div class=\"chart-scroll\">{}</div></section>",
        chart(&page.series)
    ));
    let companies = if page.by_company.is_empty() {
        "<p class=\"muted\">No active companies yet. <a href=\"/admin/companies/new\">Create the first one.</a></p>".to_string()
    } else {
        let items = page
            .by_company
            .iter()
            .map(|company| {
                format!(
                    "<li class=\"meter-row\"><div class=\"line\"><a href=\"/admin/companies/{}\"><strong>{}</strong></a><span class=\"num\">{}</span></div>{}</li>",
                    segment(&company.slug),
                    escape(&company.name),
                    escape(&usage_label(&company.usage)),
                    meter(&company.usage, &format!("{}: {}", company.name, usage_label(&company.usage)))
                )
            })
            .collect::<String>();
        format!("<ul class=\"list\">{items}</ul>")
    };
    let attention = if page.attention.is_empty() {
        "<p class=\"muted\">Nothing needs attention.</p>".to_string()
    } else {
        page.attention
            .iter()
            .map(|item| {
                format!(
                    "<div class=\"attention-item\"><strong>{} · {} · {} · {}</strong><span class=\"muted\">{} since {} UTC. {} stays held until OpenRouter confirms usage; the worker revokes it by name, or you authorize a replacement.</span><div><a class=\"button small\" href=\"/admin/companies/{}/tenants/{}\">Review</a></div></div>",
                    escape(&item.company_name),
                    escape(&item.tenant),
                    escape(&item.subject),
                    lease_pill(&item.status),
                    if item.status == "uncertain" { "Creation not confirmed" } else { "Waiting for OpenRouter" },
                    item.since.format("%H:%M"),
                    money(item.held),
                    segment(&item.company_slug),
                    segment(&item.tenant),
                )
            })
            .collect::<String>()
    };
    html.push_str(&format!(
        "<div class=\"two\"><section class=\"panel\"><div class=\"panel-head\"><h2>Today by company</h2>{}</div>{companies}</section><section class=\"panel\"><h2>Needs attention</h2>{attention}<h3>Background worker</h3><ul class=\"status-list\">{}{}</ul></section></div>",
        legend_ledger(),
        worker_row("Revocation sweep · every 15 s", now, page.worker.last_revocation, 60, page.worker.configured),
        worker_row("Usage sweep · every 60 s", now, page.worker.last_usage, 180, page.worker.configured),
    ));
    layout(ctx, Section::Overview, "Overview", notice, &html)
}

// ---------------------------------------------------------------- companies

fn company_pill(client: &ManagedClient, active_keys: usize) -> String {
    match client.suspended_at {
        Some(at) => pill("danger", &format!("Suspended {}", at.format("%b %-d"))),
        None if active_keys == 0 => pill("info", "Needs an API key"),
        None => pill("ok", "Active"),
    }
}

pub fn companies(ctx: &AdminContext, rows: &[CompanyRow], notice: Option<Notice>) -> String {
    let active = rows.iter().filter(|row| row.client.is_active()).count();
    let body = if rows.is_empty() {
        "<p class=\"muted\">No companies yet.</p>".to_string()
    } else {
        let lines = rows
            .iter()
            .map(|row| {
                let cap = match row.client.daily_cap_usd_micros {
                    Some(limit) => format!(
                        "{}<span class=\"meta num\">{} of {}</span>",
                        meter(&row.today, &usage_label(&row.today)),
                        money(row.today.spent + row.today.held),
                        money(limit)
                    ),
                    None => "<span class=\"meta\">No cap</span>".to_string(),
                };
                let keys = match (row.rotating_keys, row.revoked_keys) {
                    (0, 0) => format!("{}", row.active_keys + row.rotating_keys),
                    (0, revoked) => format!("{} <span class=\"meta\">{revoked} revoked</span>", row.active_keys),
                    (rotating, _) => format!("{} <span class=\"meta\">{rotating} rotating</span>", row.active_keys + rotating),
                };
                format!(
                    "<tr><td><span class=\"name\">{}</span><span class=\"meta mono\">{}</span></td><td>{}</td><td class=\"right num\">{}</td><td class=\"right num\">{keys}</td><td class=\"right num\">{}</td><td class=\"right num\">{}</td><td>{cap}</td><td><a class=\"button secondary small\" href=\"/admin/companies/{}\">Open</a></td></tr>",
                    escape(&row.client.name),
                    escape(&row.client.slug),
                    company_pill(&row.client, row.active_keys + row.rotating_keys),
                    row.workspaces,
                    money(row.today.spent),
                    money(row.month_spent),
                    segment(&row.client.slug),
                )
            })
            .collect::<String>();
        format!(
            "<div class=\"table-wrap\"><table><thead><tr><th>Company</th><th>Status</th><th class=\"right\">Workspaces</th><th class=\"right\">API keys</th><th class=\"right\">Today</th><th class=\"right\">This month</th><th>Daily cap</th><th><span class=\"muted\">Open</span></th></tr></thead><tbody>{lines}</tbody></table></div>"
        )
    };
    let html = format!(
        "<div class=\"page-head\"><div class=\"title\"><span class=\"eyebrow\">{} companies · {active} active</span><h1>Companies</h1></div><div class=\"actions\"><a class=\"button\" href=\"/admin/companies/new\">New company</a></div></div><section class=\"panel\">{body}</section>",
        rows.len()
    );
    layout(ctx, Section::Companies, "Companies", notice, &html)
}

pub fn company_new(ctx: &AdminContext, notice: Option<Notice>) -> String {
    let html = format!(
        "<div class=\"page-head\"><div class=\"title\"><nav class=\"crumbs\" aria-label=\"Breadcrumb\"><a href=\"/admin/companies\">Companies</a><span>/</span><span>New</span></nav><h1>New company</h1></div></div><form class=\"panel stack\" method=\"post\" action=\"/admin/companies\">{}<div class=\"fields\"><label for=\"company-name\">Name<input type=\"text\" id=\"company-name\" name=\"name\" required maxlength=\"200\"><span class=\"hint\">Shown only in this panel.</span></label><label for=\"company-slug\">Slug<input type=\"text\" id=\"company-slug\" name=\"slug\" required pattern=\"[a-z0-9][a-z0-9-]{{1,39}}\" class=\"mono\" autocapitalize=\"none\" spellcheck=\"false\"><span class=\"hint\">Prefixes every OpenRouter key name (<code>slug:daily:…</code>). Lowercase letters, digits and hyphens. It cannot change later.</span></label></div><label for=\"company-workspaces\">OpenRouter workspaces<textarea id=\"company-workspaces\" name=\"workspaces\" required spellcheck=\"false\"></textarea><span class=\"hint\">One workspace ID per line. A workspace belongs to one company only; this company's tenants can only create keys inside these.</span></label><div class=\"fields\"><label for=\"company-models\">Allowed models<input type=\"text\" id=\"company-models\" name=\"models\" value=\"openai/gpt-oss-120b\" class=\"mono\"><span class=\"hint\">Comma-separated; returned with every credential.</span></label><label for=\"company-cap\">Daily cap, USD<input type=\"text\" id=\"company-cap\" name=\"daily_cap_usd\" inputmode=\"decimal\" placeholder=\"No cap\"><span class=\"hint\">Upper bound on the sum of this company's daily tenant ceilings, checked when the company sets them.</span></label></div><label for=\"company-contact\">Technical contact <span class=\"hint\">Optional</span><input type=\"text\" id=\"company-contact\" name=\"contact\" maxlength=\"200\"></label>{}<div class=\"actions\"><button>Create company</button><a class=\"button secondary\" href=\"/admin/companies\">Cancel</a></div></form>",
        hidden("csrf", ctx.csrf()),
        step_up(
            "company-code",
            "Creating a company, changing its workspaces and every API key action ask for a fresh code, even inside an active session."
        ),
    );
    layout(ctx, Section::Companies, "New company", notice, &html)
}

fn key_pill(key: &ManagedClientKey, now: DateTime<Utc>) -> String {
    match key.state(now) {
        ClientKeyState::Active => pill("ok", "Active"),
        ClientKeyState::Rotating => pill(
            "warn",
            &format!("Rotating · until {}", key.expires_at.format("%b %-d")),
        ),
        ClientKeyState::Expired => pill("", "Expired"),
        ClientKeyState::Revoked => pill(
            "danger",
            &format!(
                "Revoked {}",
                key.revoked_at
                    .map(|at| at.format("%b %-d").to_string())
                    .unwrap_or_default()
            ),
        ),
    }
}

fn permissions(key: &ManagedClientKey) -> &'static str {
    match (key.can_issue, key.can_manage) {
        (true, true) => "Issue credentials · Manage budgets",
        (true, false) => "Issue credentials",
        _ => "Manage budgets",
    }
}

pub fn company(ctx: &AdminContext, page: &CompanyPage, notice: Option<Notice>) -> String {
    let client = &page.client;
    let slug = segment(&client.slug);
    let now = page.now;
    let status = company_pill(
        client,
        page.keys
            .iter()
            .filter(|key| {
                matches!(
                    key.state(now),
                    ClientKeyState::Active | ClientKeyState::Rotating
                )
            })
            .count(),
    );
    let contact = client
        .contact
        .as_deref()
        .map(|contact| format!(" · contact {}", escape(contact)))
        .unwrap_or_default();
    let mut html = format!(
        "<div class=\"page-head\"><div class=\"title\"><nav class=\"crumbs\" aria-label=\"Breadcrumb\"><a href=\"/admin/companies\">Companies</a><span>/</span><span>{name}</span></nav><h1>{name} {status}</h1><span class=\"muted\"><span class=\"mono\">{slug_text}</span> · created {}{contact}</span></div><div class=\"actions\"><a class=\"button secondary\" href=\"/admin/companies/{slug}/export.csv\">Export this month (CSV)</a>{create}</div></div>",
        date(client.created_at),
        name = escape(&client.name),
        slug_text = escape(&client.slug),
        create = if client.is_active() {
            format!(
                "<a class=\"button\" href=\"/admin/companies/{slug}/keys/new\">Create API key</a>"
            )
        } else {
            String::new()
        },
    );
    let available = match (page.today.limit, page.today.available()) {
        (Some(limit), Some(available)) => format!(
            "<span class=\"value\">{}</span><span class=\"sub\">of a {} daily cap</span>",
            money(available),
            money(limit)
        ),
        _ => "<span class=\"value\">—</span><span class=\"sub\">No company cap</span>".to_string(),
    };
    html.push_str(&format!(
        "<div class=\"kpis\"><div class=\"kpi\"><span class=\"label\">Spent today</span><span class=\"value\">{}</span><span class=\"sub\">{} tenants</span></div><div class=\"kpi\"><span class=\"label\">Held by live keys</span><span class=\"value\">{}</span><span class=\"sub\">{} live keys</span></div><div class=\"kpi\"><span class=\"label\">Available today</span>{available}</div><div class=\"kpi\"><span class=\"label\">This month</span><span class=\"value\">{}</span><span class=\"sub\">Keys issued today: {}{}</span></div></div>",
        money(page.today.spent),
        page.tenants.len(),
        money(page.today.held),
        page.live_keys,
        money(page.month_spent),
        page.keys_today,
        if page.migration_spent > 0 { format!(" · migration {}", money(page.migration_spent)) } else { String::new() },
    ));
    let keys = if page.keys.is_empty() {
        "<p class=\"muted\">No API keys yet. The company cannot call the API until you create one.</p>".to_string()
    } else {
        let rows = page
            .keys
            .iter()
            .map(|key| {
                let used = match (key.last_used_at, key.last_used_source.as_deref()) {
                    (Some(at), Some(source)) => format!("<span class=\"num\">{}</span><span class=\"meta mono\">{}</span>", ago(now, at), escape(source)),
                    _ => "<span class=\"meta\">Never</span>".to_string(),
                };
                let sources = key.sources().map(|ranges| ranges.iter().map(|range| range.render()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
                let actions = match key.state(now) {
                    ClientKeyState::Active | ClientKeyState::Rotating if client.is_active() => format!(
                        "<div class=\"actions\">{}<a class=\"button quiet-danger small\" href=\"/admin/companies/{slug}/keys/{}/revoke\">Revoke</a></div>",
                        if key.state(now) == ClientKeyState::Active { format!("<a class=\"button secondary small\" href=\"/admin/companies/{slug}/keys/new?replaces={}\">Rotate</a>", segment(&key.id)) } else { String::new() },
                        segment(&key.id)
                    ),
                    _ => String::new(),
                };
                format!(
                    "<tr><td><span class=\"name\">{}</span><span class=\"meta mono\">{}</span>{}</td><td>{}</td><td>{used}</td><td class=\"num\">{}</td><td>{}</td><td>{actions}</td></tr>",
                    escape(&key.label),
                    escape(&key.masked()),
                    if sources.is_empty() { String::new() } else { format!("<span class=\"meta mono\">from {}</span>", escape(&sources)) },
                    permissions(key),
                    date(key.expires_at),
                    key_pill(key, now),
                )
            })
            .collect::<String>();
        format!(
            "<div class=\"table-wrap\"><table><thead><tr><th>Key</th><th>Permissions</th><th>Last used</th><th>Expires</th><th>Status</th><th><span class=\"muted\">Actions</span></th></tr></thead><tbody>{rows}</tbody></table></div>"
        )
    };
    html.push_str(&format!(
        "<section class=\"panel\"><div class=\"panel-head\"><h2>API keys</h2><span class=\"muted\">The company backend sends one of these as <code>Authorization: Bearer …</code></span></div>{keys}</section>"
    ));
    let workspaces = page
        .workspaces
        .iter()
        .map(|workspace| {
            let remove = if workspace.tenants == 0 {
                format!("<a class=\"button quiet-danger small\" href=\"/admin/companies/{slug}/workspaces/{}/remove\">Remove</a>", segment(&workspace.workspace_id))
            } else {
                pill("ok", "In use")
            };
            format!(
                "<li><span><span class=\"mono\">{}</span><span class=\"meta\">{} tenant(s)</span></span>{remove}</li>",
                escape(&workspace.workspace_id),
                workspace.tenants
            )
        })
        .collect::<String>();
    let integration = format!(
        "<pre class=\"code\">curl https://{PUBLIC_HOST}/v1/managed/credentials \\\n  -H \"Authorization: Bearer $ASYSTANT_API_KEY\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{{\"tenant\":\"TENANT_ID\",\n       \"subject\":\"SUBJECT_ID\",\n       \"bucket\":\"daily\"}}'</pre>"
    );
    html.push_str(&format!(
        "<div class=\"two\"><section class=\"panel\"><h2>OpenRouter workspaces</h2><ul class=\"status-list\">{workspaces}</ul><form class=\"stack\" method=\"post\" action=\"/admin/companies/{slug}/workspaces\">{}<label for=\"workspace-id\">Assign another workspace<input type=\"text\" id=\"workspace-id\" name=\"workspace_id\" class=\"mono\" required spellcheck=\"false\" placeholder=\"00000000-0000-0000-0000-000000000000\"></label>{}<div class=\"actions\"><button class=\"button secondary\">Assign workspace</button></div></form><p class=\"muted\"><small>A workspace belongs to one company. It cannot be removed while a tenant budget uses it.</small></p></section><section class=\"panel\"><h2>Integration</h2><p class=\"muted\">One HTTPS call from the company backend, after it authenticates its user. No SDK needed.</p>{integration}<p class=\"muted\"><small>Returns the subject's OpenRouter key for today, its expiry and the allowed models. Full contract at <span class=\"mono\">{PUBLIC_HOST}/openapi.yaml</span>.</small></p></section></div>",
        hidden("csrf", ctx.csrf()),
        code_field("workspace-code"),
    ));
    let tenants = if page.tenants.is_empty() {
        "<p class=\"muted\">No tenant budgets yet. The company sets them through its API key.</p>"
            .to_string()
    } else {
        let rows = page
            .tenants
            .iter()
            .map(|tenant| {
                let state = if tenant.attention > 0 {
                    pill("warn", &format!("{} uncertain", tenant.attention))
                } else if tenant.live_keys == 0 {
                    pill("", "No keys today")
                } else {
                    pill("ok", "OK")
                };
                format!(
                    "<tr><td><a class=\"name mono\" href=\"/admin/companies/{slug}/tenants/{}\">{}</a><span class=\"meta mono\">{}</span></td><td class=\"right num\">{}</td><td>{}</td><td class=\"right num\">{}</td><td class=\"right num\">{}</td><td class=\"right num\">{}</td><td>{state}</td></tr>",
                    segment(&tenant.tenant),
                    escape(&tenant.tenant),
                    escape(&tenant.workspace_id),
                    money(tenant.usage.limit.unwrap_or_default()),
                    meter(&tenant.usage, &usage_label(&tenant.usage)),
                    money(tenant.usage.spent),
                    money(tenant.usage.held),
                    tenant.subjects,
                )
            })
            .collect::<String>();
        format!(
            "<div class=\"table-wrap\"><table><thead><tr><th>Tenant</th><th class=\"right\">Daily ceiling</th><th>Use of ceiling</th><th class=\"right\">Spent</th><th class=\"right\">Held</th><th class=\"right\">Subjects</th><th>State</th></tr></thead><tbody>{rows}</tbody></table></div>"
        )
    };
    html.push_str(&format!(
        "<section class=\"panel\"><div class=\"panel-head\"><h2>Tenants today</h2>{}</div>{tenants}<p class=\"muted\"><small>Ceilings and subject budgets are set by the company through its API key. Spend counts only usage confirmed by OpenRouter.</small></p></section>",
        legend_ledger()
    ));
    let models = client.models().unwrap_or_default().join(", ");
    let cap = client
        .daily_cap_usd_micros
        .map(|cap| format!("{}.{:02}", cap / 1_000_000, (cap % 1_000_000) / 10_000))
        .unwrap_or_default();
    html.push_str(&format!(
        "<section class=\"panel\"><h2>Settings</h2><form class=\"stack\" method=\"post\" action=\"/admin/companies/{slug}/settings\">{}<div class=\"fields\"><label for=\"settings-name\">Name<input type=\"text\" id=\"settings-name\" name=\"name\" value=\"{}\" required maxlength=\"200\"></label><label for=\"settings-contact\">Technical contact<input type=\"text\" id=\"settings-contact\" name=\"contact\" value=\"{}\" maxlength=\"200\"></label><label for=\"settings-models\">Allowed models<input type=\"text\" id=\"settings-models\" name=\"models\" value=\"{}\" class=\"mono\" required></label><label for=\"settings-cap\">Daily cap, USD<input type=\"text\" id=\"settings-cap\" name=\"daily_cap_usd\" value=\"{cap}\" inputmode=\"decimal\" placeholder=\"No cap\"><span class=\"hint\">It cannot go below the sum of the current daily tenant ceilings.</span></label></div>{}<div class=\"actions\"><button class=\"button secondary\">Save settings</button></div></form></section>",
        hidden("csrf", ctx.csrf()),
        escape(&client.name),
        escape(client.contact.as_deref().unwrap_or_default()),
        escape(&models),
        code_field("settings-code"),
    ));
    if client.is_active() {
        html.push_str(&format!(
            "<section class=\"panel danger-zone\"><h2>Suspend company</h2><p>Rejects all its API keys at once and queues its {} live OpenRouter keys for revocation within 15 seconds. Held money stays held until OpenRouter confirms usage. You can reactivate it later with new API keys.</p><form class=\"step-up\" method=\"post\" action=\"/admin/companies/{slug}/suspend\">{}<label for=\"suspend-slug\">Type the slug to confirm<input type=\"text\" id=\"suspend-slug\" name=\"confirm\" class=\"mono\" required autocapitalize=\"none\" spellcheck=\"false\"></label>{}<button class=\"button danger\">Suspend {}</button></form></section>",
            page.live_keys,
            hidden("csrf", ctx.csrf()),
            code_field("suspend-code"),
            escape(&client.name),
        ));
    } else {
        html.push_str(&format!(
            "<section class=\"panel\"><h2>Reactivate company</h2><p>Its API keys stay revoked; create new ones after reactivating.</p><form class=\"step-up\" method=\"post\" action=\"/admin/companies/{slug}/reactivate\">{}{}<button class=\"button\">Reactivate {}</button></form></section>",
            hidden("csrf", ctx.csrf()),
            code_field("reactivate-code"),
            escape(&client.name),
        ));
    }
    layout(ctx, Section::Companies, &client.name, notice, &html)
}

pub fn key_new(
    ctx: &AdminContext,
    client: &ManagedClient,
    rotatable: &[&ManagedClientKey],
    replaces: Option<&str>,
    notice: Option<Notice>,
) -> String {
    let slug = segment(&client.slug);
    let options = rotatable
        .iter()
        .map(|key| {
            let selected = if replaces == Some(key.id.as_str()) {
                " selected"
            } else {
                ""
            };
            format!(
                "<option value=\"{}\"{selected}>{} · {} · stays valid 7 more days</option>",
                escape(&key.id),
                escape(&key.label),
                escape(&key.masked())
            )
        })
        .collect::<String>();
    let html = format!(
        "<div class=\"page-head\"><div class=\"title\"><nav class=\"crumbs\" aria-label=\"Breadcrumb\"><a href=\"/admin/companies\">Companies</a><span>/</span><a href=\"/admin/companies/{slug}\">{name}</a><span>/</span><span>New API key</span></nav><h1>Create an API key for {name}</h1></div></div><form class=\"panel stack\" method=\"post\" action=\"/admin/companies/{slug}/keys\">{}<div class=\"fields\"><label for=\"key-label\">Label<input type=\"text\" id=\"key-label\" name=\"label\" required maxlength=\"80\" placeholder=\"Production backend\"><span class=\"hint\">Where the key lives, so you know what breaks if you revoke it.</span></label><label for=\"key-expiry\">Expires<select id=\"key-expiry\" name=\"expiry_days\"><option value=\"30\">In 30 days</option><option value=\"90\" selected>In 90 days</option><option value=\"180\">In 180 days</option><option value=\"365\">In 365 days</option></select><span class=\"hint\">Every key expires.</span></label></div><fieldset><legend>Permissions</legend><label class=\"check\" for=\"key-perm-issue\"><input type=\"checkbox\" id=\"key-perm-issue\" name=\"can_issue\" checked><span><strong>Issue credentials</strong><span class=\"muted\">POST /v1/managed/credentials: the call the company makes for each user.</span></span></label><label class=\"check\" for=\"key-perm-manage\"><input type=\"checkbox\" id=\"key-perm-manage\" name=\"can_manage\"><span><strong>Manage budgets</strong><span class=\"muted\">Tenant ceilings, subject budgets, budget overview and recovery. Give it only to the company's operations backend.</span></span></label></fieldset><div class=\"fields\"><label for=\"key-sources\">Allowed source addresses <span class=\"hint\">Optional</span><textarea id=\"key-sources\" name=\"allowed_sources\" spellcheck=\"false\" placeholder=\"203.0.113.24/32\"></textarea><span class=\"hint\">One IP or CIDR per line. Requests from anywhere else are refused even with a valid key.</span></label><label for=\"key-replaces\">Replaces<select id=\"key-replaces\" name=\"replaces\"><option value=\"\">Nothing: add a key</option>{options}</select><span class=\"hint\">Rotation: both keys work during the overlap, so the company can deploy without downtime.</span></label></div>{}<div class=\"actions\"><button>Create API key</button><a class=\"button secondary\" href=\"/admin/companies/{slug}\">Cancel</a></div></form>",
        hidden("csrf", ctx.csrf()),
        step_up(
            "key-code",
            "The key is generated on the server from 256 random bits and shown once on the next page."
        ),
        name = escape(&client.name),
    );
    layout(ctx, Section::Companies, "New API key", notice, &html)
}

pub fn key_created(ctx: &AdminContext, client: &ManagedClient, created: &CreatedKey) -> String {
    let key = &created.key;
    let secret = escape(created.api_key.expose());
    let sources = key
        .sources()
        .map(|ranges| {
            ranges
                .iter()
                .map(|range| range.render())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let html = format!(
        "<div class=\"page-head\"><div class=\"title\"><nav class=\"crumbs\" aria-label=\"Breadcrumb\"><a href=\"/admin/companies\">Companies</a><span>/</span><a href=\"/admin/companies/{slug}\">{name}</a><span>/</span><span>API key created</span></nav><h1>Copy the key now</h1></div></div><section class=\"panel\"><div class=\"notice warn\">This is the only time the key is shown. The server keeps only its SHA-256 hash and cannot show it again. If you lose it, create a new one.</div><div class=\"secret\" aria-label=\"New API key\">{secret}</div><p class=\"muted\"><small>Click the key to select all of it. Nothing on this page is cached (<code>Cache-Control: no-store</code>).</small></p><dl class=\"facts\"><dt>Label</dt><dd>{}</dd><dt>Permissions</dt><dd>{}</dd><dt>Allowed from</dt><dd class=\"mono\">{}</dd><dt>Expires</dt><dd>{}</dd></dl><h2>Put it in the company backend's secret manager</h2><pre class=\"code\">ASYSTANT_API_URL=https://{PUBLIC_HOST}\nASYSTANT_API_KEY={secret}</pre><p class=\"muted\"><small>Never in an app, a browser or a repository. The <code>ask_live_</code> prefix lets secret scanners such as GitHub's detect a leaked key.</small></p><div class=\"actions\"><a class=\"button\" href=\"/admin/companies/{slug}\">I stored the key</a></div></section>",
        escape(&key.label),
        permissions(key),
        if sources.is_empty() {
            "Anywhere".to_string()
        } else {
            escape(&sources)
        },
        date(key.expires_at),
        slug = segment(&client.slug),
        name = escape(&client.name),
    );
    layout(ctx, Section::Companies, "API key created", None, &html)
}

/// A confirmation page for a destructive action: what happens, then a code.
pub fn confirm(
    ctx: &AdminContext,
    title: &str,
    message: &str,
    action: &str,
    button: &str,
    back: &str,
) -> String {
    let html = format!(
        "<div class=\"page-head\"><div class=\"title\"><h1>{}</h1></div></div><form class=\"panel stack\" method=\"post\" action=\"{}\">{}<p>{}</p>{}<div class=\"actions\"><button class=\"button danger\">{}</button><a class=\"button secondary\" href=\"{}\">Cancel</a></div></form>",
        escape(title),
        escape(action),
        hidden("csrf", ctx.csrf()),
        escape(message),
        code_field("confirm-code"),
        escape(button),
        escape(back),
    );
    layout(ctx, Section::Companies, title, None, &html)
}

pub fn tenant(ctx: &AdminContext, page: &TenantPage, notice: Option<Notice>) -> String {
    let slug = segment(&page.client.slug);
    let tenant_segment = segment(&page.tenant);
    let rows = page
        .subjects
        .iter()
        .map(|subject| {
            let (status, limit, used, held, action) = match &subject.lease {
                Some(lease) => (
                    format!("{}<span class=\"meta\">{}</span>", lease_pill(&lease.status), if lease.status == "issued" { format!("expires {} UTC", lease.expires_at.format("%H:%M")) } else { format!("since {} UTC", lease.updated_at.format("%H:%M")) }),
                    money(lease.limit),
                    if lease.accounted > 0 { money(lease.accounted) } else { "—".to_string() },
                    money(lease.held),
                    if lease.can_recover { format!("<a class=\"button small\" href=\"#recovery-{}\">Authorize recovery</a>", escape(&lease.id)) } else { String::new() },
                ),
                None => (pill("", "None yet"), "—".to_string(), "—".to_string(), "—".to_string(), String::new()),
            };
            format!(
                "<tr><td class=\"mono\">{}</td><td class=\"right num\">{}</td><td>{status}</td><td class=\"right num\">{limit}</td><td class=\"right num\">{used}</td><td class=\"right num\">{held}</td><td>{action}</td></tr>",
                escape(&subject.subject),
                money(subject.budget),
            )
        })
        .collect::<String>();
    let recoveries = page
        .subjects
        .iter()
        .filter_map(|subject| subject.lease.as_ref().filter(|lease| lease.can_recover).map(|lease| (subject, lease)))
        .map(|(subject, lease)| {
            let room = (subject.budget - lease.held).max(0);
            format!(
                "<section class=\"panel\" id=\"recovery-{id}\"><h2>Authorize recovery for {}</h2><p class=\"muted\">Reserves a new allocation for today and queues the uncertain one for revocation by name. The uncertain {} stays held until OpenRouter confirms its usage, so the new limit must fit in what is left.</p><form class=\"stack\" method=\"post\" action=\"/admin/companies/{slug}/tenants/{tenant_segment}/leases/{id}/recovery\">{}<div class=\"fields\"><label for=\"recovery-limit-{id}\">New limit, USD<input type=\"text\" id=\"recovery-limit-{id}\" name=\"limit_usd\" inputmode=\"decimal\" required><span class=\"hint\">Up to {}: the subject budget minus what is held.</span></label><label for=\"recovery-reason-{id}\">Reason<input type=\"text\" id=\"recovery-reason-{id}\" name=\"reason\" minlength=\"10\" maxlength=\"500\" required></label></div><label class=\"check\" for=\"recovery-ack-{id}\"><input type=\"checkbox\" id=\"recovery-ack-{id}\" name=\"acknowledge\" required><span><strong>The uncertain reservation stays held</strong><span class=\"muted\">It is released only by a usage observation from OpenRouter.</span></span></label><div class=\"step-up\">{}<button>Authorize recovery</button></div></form></section>",
                escape(&subject.subject),
                money(lease.held),
                hidden("csrf", ctx.csrf()),
                money(room),
                code_field(&format!("recovery-code-{}", lease.id)),
                id = escape(&lease.id),
            )
        })
        .collect::<String>();
    let workspace = page.workspace_id.as_deref().map(escape).unwrap_or_default();
    let html = format!(
        "<div class=\"page-head\"><div class=\"title\"><nav class=\"crumbs\" aria-label=\"Breadcrumb\"><a href=\"/admin/companies\">Companies</a><span>/</span><a href=\"/admin/companies/{slug}\">{}</a><span>/</span><span>{tenant}</span></nav><h1 class=\"mono\">{tenant}</h1><span class=\"muted\">Workspace <span class=\"mono\">{workspace}</span> · daily ceiling {} · set by the company</span></div></div><section class=\"panel\"><div class=\"meter-row\"><div class=\"line\"><strong>Today</strong><span class=\"num\">{}</span></div>{}</div><div class=\"table-wrap\"><table><thead><tr><th>Subject</th><th class=\"right\">Daily budget</th><th>Key today</th><th class=\"right\">Key limit</th><th class=\"right\">Confirmed use</th><th class=\"right\">Held</th><th><span class=\"muted\">Action</span></th></tr></thead><tbody>{rows}</tbody></table></div></section>{recoveries}",
        escape(&page.client.name),
        money(page.usage.limit.unwrap_or_default()),
        escape(&usage_label(&page.usage)),
        meter(&page.usage, &usage_label(&page.usage)),
        tenant = escape(&page.tenant),
    );
    layout(ctx, Section::Companies, &page.tenant, notice, &html)
}

// ---------------------------------------------------------------- audit

pub fn audit(ctx: &AdminContext, page: &AuditPage) -> String {
    let options = page
        .companies
        .iter()
        .map(|client| {
            let selected = if page.filter.as_deref() == Some(client.slug.as_str()) {
                " selected"
            } else {
                ""
            };
            format!(
                "<option value=\"{}\"{selected}>{}</option>",
                escape(&client.slug),
                escape(&client.name)
            )
        })
        .collect::<String>();
    let rows = page
        .entries
        .iter()
        .map(|entry| {
            let result = if entry.result == "done" { pill("ok", "Done") } else { pill("danger", "Refused") };
            let actor = entry.actor.as_deref().map(escape).unwrap_or_else(|| "<span class=\"muted\">unknown</span>".to_string());
            let detail = if entry.detail.is_empty() { String::new() } else { format!("<span class=\"meta\">{}</span>", escape(&entry.detail)) };
            format!(
                "<tr><td class=\"num\">{}</td><td>{actor}</td><td><span class=\"name\">{} · {}</span>{detail}</td><td class=\"mono\">{}</td><td>{result}</td></tr>",
                stamp(entry.created_at),
                escape(&entry.action),
                escape(&entry.target),
                escape(&entry.source),
            )
        })
        .collect::<String>();
    let html = format!(
        "<div class=\"page-head\"><div class=\"title\"><span class=\"eyebrow\">Append-only · latest 200</span><h1>Audit log</h1></div><form class=\"actions\" method=\"get\" action=\"/admin/audit\"><select id=\"audit-company\" name=\"company\" aria-label=\"Company\"><option value=\"\">All companies</option>{options}</select><button class=\"button secondary\">Filter</button></form></div><section class=\"panel\"><div class=\"table-wrap\"><table><thead><tr><th>Time (UTC)</th><th>Who</th><th>What</th><th>Source</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table></div><p class=\"muted\"><small>The database refuses to edit or delete entries. Secrets and keys never appear here, only their prefixes.</small></p></section>"
    );
    layout(ctx, Section::Audit, "Audit log", None, &html)
}

// ---------------------------------------------------------------- security

pub fn security(ctx: &AdminContext, page: &SecurityPage, notice: Option<Notice>) -> String {
    let now = Utc::now();
    let sessions = page
        .sessions
        .iter()
        .map(|session| {
            let current = session.id == page.current_session;
            let action = if current {
                String::new()
            } else {
                format!(
                    "<form method=\"post\" action=\"/admin/security/sessions/{}/revoke\">{}<button class=\"button quiet-danger small\">Sign out</button></form>",
                    segment(&session.id),
                    hidden("csrf", ctx.csrf())
                )
            };
            format!(
                "<tr><td><span class=\"name\">{}</span>{}</td><td class=\"mono\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td>{action}</td></tr>",
                escape(&session.user_agent.chars().take(80).collect::<String>()),
                if current { "<span class=\"meta\">This session</span>" } else { "" },
                escape(&session.source),
                stamp(session.created_at),
                ago(now, session.last_seen_at),
            )
        })
        .collect::<String>();
    let system = &page.system;
    let last_sign_in = match (
        page.admin.last_sign_in_at,
        page.admin.last_sign_in_source.as_deref(),
    ) {
        (Some(at), Some(source)) => format!("{} from {}", stamp(at), escape(source)),
        _ => "Never".to_string(),
    };
    let html = format!(
        "<div class=\"page-head\"><div class=\"title\"><span class=\"eyebrow\">Your account and the system</span><h1>Security</h1></div></div><section class=\"panel\"><div class=\"panel-head\"><h2>Active sessions</h2><form method=\"post\" action=\"/admin/security/sessions/revoke-others\">{csrf}<button class=\"button secondary small\">Sign out all other sessions</button></form></div><div class=\"table-wrap\"><table><thead><tr><th>Device</th><th>Source</th><th>Started</th><th>Last activity</th><th><span class=\"muted\">Action</span></th></tr></thead><tbody>{sessions}</tbody></table></div></section><div class=\"two\"><section class=\"panel\"><h2>Your account</h2><dl class=\"facts\"><dt>Username</dt><dd>{}</dd><dt>Password</dt><dd>Changed {} · argon2id</dd><dt>Authenticator</dt><dd>{}</dd><dt>Last sign-in</dt><dd>{last_sign_in}</dd></dl><h3>Change password</h3><form class=\"stack\" method=\"post\" action=\"/admin/security/password\">{csrf}<label for=\"password-current\">Current password<input type=\"password\" id=\"password-current\" name=\"current\" autocomplete=\"current-password\" required></label><label for=\"password-next\">New password<input type=\"password\" id=\"password-next\" name=\"next\" autocomplete=\"new-password\" minlength=\"12\" maxlength=\"256\" required><span class=\"hint\">At least 12 characters. Your other sessions sign out.</span></label>{}<div class=\"actions\"><button class=\"button secondary\">Change password</button></div></form><h3>Replace authenticator</h3><form class=\"stack\" method=\"post\" action=\"/admin/security/authenticator\">{csrf}<label for=\"totp-password\">Password<input type=\"password\" id=\"totp-password\" name=\"password\" autocomplete=\"current-password\" required></label>{}<div class=\"actions\"><button class=\"button secondary\">Replace authenticator</button></div></form></section><section class=\"panel\"><h2>System</h2><ul class=\"status-list\"><li><span>OpenRouter management key</span>{}</li><li><span>Key encryption (XChaCha20-Poly1305)</span>{}</li>{}{}<li><span>Version</span><span class=\"mono\">asystant-api {}</span></li></ul></section></div><section class=\"panel\"><h2>How this panel is protected</h2><ul class=\"controls\"><li><strong>No JavaScript at all.</strong> The policy <code>default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'</code> forbids every script, so injected markup cannot run.</li><li><strong>Password plus authenticator.</strong> argon2id password and a 6-digit TOTP code on every sign-in; the TOTP secret is stored encrypted and a code can be used only once.</li><li><strong>Fresh code for sensitive actions.</strong> Creating companies, changing workspaces and settings, and creating or revoking API keys ask for a new code.</li><li><strong>Sessions.</strong> 256-bit random, stored as a hash, <code>__Host-</code> cookie (Secure, HttpOnly, SameSite=Strict), 30 minutes idle and 8 hours in total, revocable here.</li><li><strong>Forged requests.</strong> A per-session token on every form, SameSite=Strict and an Origin check that only accepts this host.</li><li><strong>Guessing.</strong> Five failed sign-ins lock the account and the address for 15 minutes; errors never say which part was wrong.</li><li><strong>API keys.</strong> <code>ask_live_</code> + 43 random characters (256 bits) + a checksum; shown once, stored as SHA-256, with expiry, permissions, optional source addresses, last use and instant revocation.</li><li><strong>Transport and caching.</strong> HTTPS only with HSTS; <code>Cache-Control: no-store</code>, no referrer sent to other sites and no third-party requests on every page.</li><li><strong>Audit.</strong> Every sign-in and change is appended with who, when and from where.</li></ul></section>",
        escape(&page.admin.username),
        date(page.admin.password_changed_at),
        pill("ok", "On"),
        code_field("password-code"),
        code_field("totp-code"),
        if system.managed_configured {
            pill("ok", "Configured")
        } else {
            pill("warn", "Not configured: keys cannot be issued")
        },
        pill("ok", "Configured"),
        worker_row(
            "Revocation sweep",
            now,
            system.worker.last_revocation,
            60,
            system.worker.configured
        ),
        worker_row(
            "Usage sweep",
            now,
            system.worker.last_usage,
            180,
            system.worker.configured
        ),
        escape(&system.version),
        csrf = hidden("csrf", ctx.csrf()),
    );
    layout(ctx, Section::Security, "Security", notice, &html)
}

pub fn totp_enrollment(ctx: &AdminContext, enrollment: &TotpEnrollment) -> String {
    let html = format!(
        "<div class=\"page-head\"><div class=\"title\"><nav class=\"crumbs\" aria-label=\"Breadcrumb\"><a href=\"/admin/security\">Security</a><span>/</span><span>New authenticator</span></nav><h1>Add the new authenticator</h1></div></div><section class=\"panel stack\"><p>Add the new authenticator, then enter the code it shows. The old one keeps working until then.</p>{}<form class=\"stack\" method=\"post\" action=\"/admin/security/authenticator/confirm\">{}<label for=\"enroll-code\">Code from the new authenticator<input class=\"code-input\" type=\"text\" id=\"enroll-code\" name=\"code\" inputmode=\"numeric\" pattern=\"[0-9 ]{{6,7}}\" autocomplete=\"one-time-code\" required></label><div class=\"actions\"><button>Replace authenticator</button><a class=\"button secondary\" href=\"/admin/security\">Cancel</a></div></form></section>",
        authenticator(&enrollment.uri, &enrollment.secret),
        hidden("csrf", ctx.csrf()),
    );
    layout(ctx, Section::Security, "New authenticator", None, &html)
}

pub fn not_found(ctx: &AdminContext) -> String {
    layout(
        ctx,
        Section::Overview,
        "Not found",
        None,
        "<div class=\"page-head\"><div class=\"title\"><h1>Not found</h1></div></div><section class=\"panel\"><p>That page does not exist or the item was removed.</p><div class=\"actions\"><a class=\"button secondary\" href=\"/admin\">Back to the overview</a></div></section>",
    )
}
