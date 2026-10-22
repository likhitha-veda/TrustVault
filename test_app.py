
import io
import os
import pytest

import app as trustvault


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Use a separate temporary database for every test.
    test_db = tmp_path / "test_trustvault.db"
    test_uploads = tmp_path / "private_documents"
    test_uploads.mkdir()

    monkeypatch.setattr(
        trustvault, "DATABASE", str(test_db)
    )
    monkeypatch.setattr(
        trustvault, "UPLOAD_FOLDER", str(test_uploads)
    )

    trustvault.app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret-key",
    )

    trustvault.init_db()

    with trustvault.app.test_client() as test_client:
        yield test_client


def login(client, username, password):
    return client.post(
        "/",
        data={
            "username": username,
            "password": password,
        },
        follow_redirects=True,
    )


def upload_test_document(client):
    response = client.post(
        "/upload",
        data={
            "document": (
                io.BytesIO(b"TrustVault test document"),
                "test.pdf",
            )
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200

    with trustvault.db_session() as db:
        document = db.execute(
            """
            SELECT id FROM documents
            WHERE owner = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            ("owner",),
        ).fetchone()

    assert document is not None
    return document["id"]


def test_owner_can_upload_document(client):
    login(client, "owner", "Owner123")

    document_id = upload_test_document(client)

    file_path = os.path.join(
        trustvault.UPLOAD_FOLDER, document_id
    )
    assert os.path.isfile(file_path)


def test_viewer_cannot_upload(client):
    login(client, "viewer", "Viewer123")

    response = client.get("/upload")

    assert response.status_code == 403


def test_viewer_cannot_view_audit_logs(client):
    login(client, "viewer", "Viewer123")

    response = client.get("/audit")

    assert response.status_code == 403


def test_viewer_cannot_download_without_permission(client):
    login(client, "owner", "Owner123")
    document_id = upload_test_document(client)

    # A separate client represents the viewer.
    viewer_client = trustvault.app.test_client()
    login(viewer_client, "viewer", "Viewer123")

    response = viewer_client.get(
        f"/document/{document_id}"
    )

    assert response.status_code == 403


def test_revoked_permission_blocks_download(client):
    login(client, "owner", "Owner123")
    document_id = upload_test_document(client)

    # Grant viewer read access.
    grant_response = client.post(
        f"/share/{document_id}",
        data={
            "target_user": "viewer",
            "access": "read",
        },
    )
    assert grant_response.status_code == 200

    viewer_client = trustvault.app.test_client()
    login(viewer_client, "viewer", "Viewer123")

    # Viewer can download while permission exists.
    allowed = viewer_client.get(
        f"/document/{document_id}"
    )
    assert allowed.status_code == 200

    # Owner revokes viewer's permission.
    revoke_response = client.post(
        f"/share/{document_id}",
        data={
            "target_user": "viewer",
            "access": "revoke",
        },
    )
    assert revoke_response.status_code == 200

    # The same viewer must now be denied.
    denied = viewer_client.get(
        f"/document/{document_id}"
    )
    assert denied.status_code == 403


def test_admin_can_view_audit_logs(client):
    login(client, "admin", "Admin123")

    response = client.get("/audit")

    assert response.status_code == 200
    assert b"Audit Logs" in response.data
