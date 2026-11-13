//! Private, bounded SVG previews. Scene strings never become SVG markup.
use super::*;
use axum::response::{IntoResponse, Response};

fn escape(text: &str) -> String {
    text.chars()
        .take(400)
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&apos;".into(),
            c if c.is_control() => " ".into(),
            c => c.to_string(),
        })
        .collect()
}
fn number(element: &Value, key: &str) -> f64 {
    element[key]
        .as_f64()
        .filter(|n| n.is_finite())
        .unwrap_or(0.)
        .clamp(-1e7, 1e7)
}
fn color(element: &Value, key: &str, fallback: &str) -> String {
    let value = element[key].as_str().unwrap_or(fallback);
    if value == "transparent" {
        return "none".into();
    }
    if value.starts_with('#')
        && [4, 7, 9].contains(&value.len())
        && value[1..].chars().all(|c| c.is_ascii_hexdigit())
    {
        value.into()
    } else {
        fallback.into()
    }
}
pub(super) async fn read(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let _life = app.account_lifecycle.read().await;
    let row = load_scene(&app, &id).await?;
    authorize(&app, &row, &headers).await?;
    if row.get_i64("preview_revision").ok() == row.get_i64("revision").ok() {
        if let Some(cached) = app
            .collection(COLLECTION)
            .find_one(doc! {"_id":&id,"revision":row.get_i64("revision").unwrap_or(0)})
            .projection(doc! {"preview":1})
            .await?
        {
            if let Ok(bytes) = cached.get_binary_generic("preview") {
                return Ok((
                    [
                        ("content-type", "image/png"),
                        ("x-content-type-options", "nosniff"),
                    ],
                    bytes.clone(),
                )
                    .into_response());
            }
        }
    }
    let elements: Vec<Value> = row
        .get_array("elements")
        .map(|items| {
            items
                .iter()
                .filter_map(|item| serde_json::to_value(item).ok())
                .filter(|item| item["isDeleted"] != true)
                .take(500)
                .collect()
        })
        .unwrap_or_default();
    let (mut left, mut top, mut right, mut bottom) = (
        f64::INFINITY,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NEG_INFINITY,
    );
    for e in &elements {
        let (x, y, w, h) = (
            number(e, "x"),
            number(e, "y"),
            number(e, "width").abs(),
            number(e, "height").abs(),
        );
        left = left.min(x);
        top = top.min(y);
        right = right.max(x + w);
        bottom = bottom.max(y + h);
    }
    if elements.is_empty() {
        left = 0.;
        top = 0.;
        right = 240.;
        bottom = 150.;
    }
    let width = (right - left).max(40.);
    let height = (bottom - top).max(40.);
    let pad = width.max(height) * 0.06;
    let mut svg=format!("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"240\" height=\"150\" viewBox=\"{} {} {} {}\"><rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"#fff\"/>",left-pad,top-pad,width+pad*2.,height+pad*2.,left-pad,top-pad,width+pad*2.,height+pad*2.);
    for e in elements {
        let (x, y, w, h) = (
            number(&e, "x"),
            number(&e, "y"),
            number(&e, "width").abs(),
            number(&e, "height").abs(),
        );
        let stroke = color(&e, "strokeColor", "#343a40");
        let fill = color(&e, "backgroundColor", "none");
        let angle = number(&e, "angle").to_degrees();
        svg.push_str(&format!("<g transform=\"rotate({angle} {} {})\" stroke=\"{stroke}\" fill=\"{fill}\" stroke-width=\"{}\">",x+w/2.,y+h/2.,number(&e,"strokeWidth").clamp(1.,10.)));
        match e["type"].as_str().unwrap_or("") {
            "text" => {
                let size = number(&e, "fontSize").clamp(8., 200.);
                for (i, line) in e["text"]
                    .as_str()
                    .unwrap_or("")
                    .lines()
                    .take(20)
                    .enumerate()
                {
                    svg.push_str(&format!("<text x=\"{x}\" y=\"{}\" font-size=\"{size}\" font-family=\"sans-serif\" stroke=\"none\" fill=\"{stroke}\">{}</text>",y+size*(1.+i as f64*1.25),escape(line)));
                }
            }
            "ellipse" => svg.push_str(&format!(
                "<ellipse cx=\"{}\" cy=\"{}\" rx=\"{}\" ry=\"{}\"/>",
                x + w / 2.,
                y + h / 2.,
                w / 2.,
                h / 2.
            )),
            "diamond" => svg.push_str(&format!(
                "<polygon points=\"{},{} {},{} {},{} {},{}\"/>",
                x + w / 2.,
                y,
                x + w,
                y + h / 2.,
                x + w / 2.,
                y + h,
                x,
                y + h / 2.
            )),
            "line" | "arrow" | "freedraw" => {
                let points = e["points"]
                    .as_array()
                    .map(|points| {
                        points
                            .iter()
                            .take(2000)
                            .filter_map(|p| {
                                Some(format!(
                                    "{},{}",
                                    x + p[0].as_f64()?.clamp(-1e7, 1e7),
                                    y + p[1].as_f64()?.clamp(-1e7, 1e7)
                                ))
                            })
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();
                svg.push_str(&format!("<polyline fill=\"none\" points=\"{points}\"/>"));
            }
            "rectangle" | "frame" | "image" => svg.push_str(&format!(
                "<rect x=\"{x}\" y=\"{y}\" width=\"{w}\" height=\"{h}\" rx=\"3\"/>"
            )),
            _ => {}
        }
        svg.push_str("</g>");
    }
    svg.push_str("</svg>");
    Ok((
        [
            ("content-type", "image/svg+xml"),
            ("x-content-type-options", "nosniff"),
            ("content-security-policy", "default-src 'none'; sandbox"),
        ],
        svg,
    )
        .into_response())
}

#[derive(Deserialize)]
pub(super) struct Thumbnail {
    revision: i64,
    image: String,
}
pub(super) async fn write(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Thumbnail>,
) -> ApiResult<StatusCode> {
    let _life = app.account_lifecycle.read().await;
    if body.image.len() > 512 * 1024 {
        return Err(ApiError::bad_request("Preview is too large"));
    }
    let row = load(&app, &id).await?;
    if !authorize(&app, &row, &headers).await?.edit {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "This board link is view-only",
        ));
    }
    let bytes = STANDARD
        .decode(&body.image)
        .map_err(|_| ApiError::bad_request("Invalid preview"))?;
    // Inspect dimensions before decoding to bound memory for untrusted input.
    if bytes.len() < 24 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" {
        return Err(ApiError::bad_request("Preview must be PNG"));
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
    let height = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
    if width == 0 || height == 0 || width > 384 || height > 384 {
        return Err(ApiError::bad_request(
            "Preview dimensions exceed 384 pixels",
        ));
    }
    let (bytes, _, _) =
        tokio::task::spawn_blocking(move || crate::hosted_images::normalize(&bytes))
            .await
            .map_err(|_| ApiError::bad_request("Invalid preview"))??;
    let _lock = app.boards.lock.lock().await;
    let row = load(&app, &id).await?;
    if !authorize(&app, &row, &headers).await?.edit {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "This board link is view-only",
        ));
    }
    let saved=app.collection(COLLECTION).update_one(doc!{"_id":id,"revision":body.revision},doc!{"$set":{"preview":bson::Binary{subtype:bson::spec::BinarySubtype::Generic,bytes},"preview_revision":body.revision}}).await?;
    if saved.matched_count == 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Board changed; retry preview",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}
