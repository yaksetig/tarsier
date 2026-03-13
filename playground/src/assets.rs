// Static asset and simple GET handlers.

use super::*;

pub(crate) async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

pub(crate) async fn app_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../static/app.js"),
    )
}

pub(crate) async fn visual_model_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../static/visual-model.js"),
    )
}

pub(crate) async fn visual_editor_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../static/visual-editor.js"),
    )
}

pub(crate) async fn codegen_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../static/codegen.js"),
    )
}

pub(crate) async fn health() -> Json<Value> {
    Json(json!({"ok": true}))
}

pub(crate) async fn list_examples(State(state): State<Arc<AppState>>) -> Json<Vec<ExampleSnippet>> {
    Json(state.examples.clone())
}
