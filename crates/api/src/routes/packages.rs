use arch_fos_common::{ApiErrorBody, InstallReason, Package, PackageFilterQuery, PackagesPage};
use axum::Json;
use axum::extract::{Query, State};
use sqlx::{QueryBuilder, Sqlite};

use crate::routes::{ApiError, AppState, normalize_limit};

#[derive(sqlx::FromRow)]
struct PackageRow {
    name: String,
    version: String,
    repo: Option<String>,
    is_foreign: i64,
    install_date: Option<i64>,
    reason: String,
    description: Option<String>,
    size_bytes: i64,
    files: String,
    first_seen_at: i64,
    last_seen_at: i64,
}

/// Lists installed packages from the ALPM inventory with cursor pagination and filters.
#[utoipa::path(
    get,
    path = "/api/v1/packages",
    tag = "packages",
    params(PackageFilterQuery),
    responses(
        (status = 200, description = "Paginated packages", body = PackagesPage),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn list_packages(
    State(state): State<AppState>,
    Query(query): Query<PackageFilterQuery>,
) -> Result<Json<PackagesPage>, ApiError> {
    let limit = normalize_limit(query.limit);

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT name, version, repo, is_foreign, install_date, reason, description, size_bytes, files, first_seen_at, last_seen_at FROM packages WHERE 1=1",
    );

    if let Some(ref cursor) = query.cursor
        && !cursor.is_empty()
    {
        qb.push(" AND name > ").push_bind(cursor);
    }
    if query.foreign_only == Some(true) {
        qb.push(" AND is_foreign = 1");
    }
    if let Some(ref repo) = query.repo
        && !repo.is_empty()
    {
        qb.push(" AND repo = ").push_bind(repo);
    }
    if let Some(ref search) = query.q
        && !search.trim().is_empty()
    {
        let pattern = format!("%{}%", search.trim());
        qb.push(" AND (name LIKE ")
            .push_bind(pattern.clone())
            .push(" OR COALESCE(description, '') LIKE ")
            .push_bind(pattern)
            .push(")");
    }

    qb.push(" ORDER BY name ASC LIMIT ").push_bind(limit + 1);

    let rows: Vec<PackageRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    let has_more = i64::try_from(rows.len()).unwrap_or(0) > limit;
    let take_count = usize::try_from(limit).unwrap_or(50);

    let items: Vec<Package> = rows
        .into_iter()
        .take(take_count)
        .map(|row| Package {
            name: row.name,
            version: row.version,
            repo: row.repo,
            is_foreign: row.is_foreign != 0,
            install_date: row.install_date,
            reason: InstallReason::parse(&row.reason).unwrap_or(InstallReason::Explicit),
            description: row.description,
            size_bytes: row.size_bytes,
            files: serde_json::from_str(&row.files).unwrap_or_default(),
            first_seen_at: row.first_seen_at,
            last_seen_at: row.last_seen_at,
        })
        .collect();

    let next_cursor = if has_more {
        items.last().map(|p| p.name.clone())
    } else {
        None
    };

    Ok(Json(PackagesPage {
        items,
        next_cursor,
        has_more,
    }))
}
