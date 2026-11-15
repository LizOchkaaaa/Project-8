import pytest
import allure
from flask.testing import FlaskClient
from app.main import MAX_TEXT_LENGTH, create_app


@pytest.fixture()
def client() -> FlaskClient:
    """
    New app for each tests.
    """
    return create_app().test_client()


@allure.feature("Pytests")
@allure.story("Test for checking status server")
def test_health(client: FlaskClient) -> None:
    """
    Checks the endpoint /health.
    """

    with allure.step("Sending a GET request to /health"):
        r = client.get("/health")

    with allure.step("Check status HTTP code"):
        assert r.status_code == 200, f"Expected code 200, but received {r.status_code}"
        allure.attach(
            str(r.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )

    with allure.step("Check body answer"):
        assert r.get_json() == {"status": "ok"}, f"Expected status - ok, but received {r.get_json()}"
        allure.attach(
            str(r.get_json()),
            name="Response JSON",
            attachment_type=allure.attachment_type.JSON
        )


@allure.story("Test for checking main HTML page")
def test_index(client: FlaskClient) -> None:
    """
    Checks the main HTML page and verifies that it contains the word "Заметки".
    """

    with allure.step("Sending a GET request to /"):
        r = client.get("/")

    with allure.step("Check status HTTP code"):
        assert r.status_code == 200, f"Expected code 200, but received {r.status_code}"
        allure.attach(
            str(r.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )

    with allure.step("Check body answer"):
        assert r.content_type.startswith("text/html"), f"Expected text/html, but received {r.content_type}"
        allure.attach(
            str(r.content_type),
            name="Content-Type",
            attachment_type=allure.attachment_type.TEXT
        )

        html_content = r.get_data(as_text=True)
        assert "Заметки" in html_content, "The word 'Заметки' was not found on the page. The template may not have loaded"
        allure.attach(
            html_content,
            name="Response HTML",
            attachment_type=allure.attachment_type.HTML
        )

@allure.story("Test for checking GET /api/items on an empty storage")
def test_list_empty(client: FlaskClient) -> None:
    """
    Checks GET /api/items on an empty storage
    """

    with allure.step("Sending a GET request to /api/items"):
        r = client.get("/api/items")
        response_json = r.get_json()
        allure.attach(
            str(response_json),
            name="Response JSON",
            attachment_type=allure.attachment_type.JSON
        )

    with allure.step("Check status HTTP code"):
        assert r.status_code == 200, f"Expected code 200, but received {r.status_code}"
        allure.attach(
            str(r.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )

    with allure.step("Check body answer is empty list"):
        assert response_json == {"items": []}, f"An empty list was expected, but received: {response_json}"
        allure.attach(
            str(response_json),
            name="Confirmed Response",
            attachment_type=allure.attachment_type.JSON
        )

@allure.story("Test for checking creation a note and its appearance in the list")
def test_create_and_list(client: FlaskClient) -> None:
    """
    Checks the creation of a note and its appearance in the list.
    """
    
    payload = {"text": "  hello  "}
    
    with allure.step(f"Send request to /api/items with data: {payload}"):
        r = client.post("/api/items", json=payload)
        allure.attach(
            str(r.get_json()),
            name="Response JSON",
            attachment_type=allure.attachment_type.JSON
        )

    with allure.step("Check HTTP status code"):
        assert r.status_code == 201, f"Expected code 201, but received {r.status_code}"
        allure.attach(
            str(r.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )

    with allure.step("Check that spaces were trimmed and ID is correct"):
        expected_item = {"id": 1, "text": "hello"}
        actual_item = r.get_json()
        assert actual_item == expected_item, f"Expected {expected_item}, but received {actual_item}"
        allure.attach(
            str(actual_item),
            name="Actual data",
            attachment_type=allure.attachment_type.TEXT
        )

    with allure.step("Send request to /api/items to verify the list"):
        list_response = client.get("/api/items")
        list_json = list_response.get_json()

    with allure.step("Check that the list contains exactly our new note"):
        expected_list = {"items": [{"id": 1, "text": "hello"}]}
        assert list_json == expected_list, f"Expected {expected_list}, but received {list_json}"
        allure.attach(
            str(list_json),
            name="Items List",
            attachment_type=allure.attachment_type.JSON
        )

@allure.story("Test for checking deleting a note")
def test_delete_item(client: FlaskClient) -> None:
    """
    Checks the deletion of a note.
    """

    with allure.step("Create a note"):
        payload = {"text": "удалить меня"}
        r = client.post("/api/items", json=payload)
        item_id = r.get_json()["id"]
        allure.attach(
            str(payload),
            name="Created Note Payload",
            attachment_type=allure.attachment_type.JSON
        )

    with allure.step("Check HTTP status code"):
        assert r.status_code == 201, f"Failed to create note. Code: {r.status_code}"
        allure.attach(
            str(r.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )
        
    with allure.step(f"Send DELETE request to /api/items/{item_id}"):
        r_delete = client.delete(f"/api/items/{item_id}")
        allure.attach(
            str(r_delete.get_json()),
            name="Delete Response",
            attachment_type=allure.attachment_type.JSON
        )

    with allure.step("Check HTTP status code"):
        assert r_delete.status_code == 200, f"Expected code 200, but received {r_delete.status_code}"
        allure.attach(
            str(r_delete.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )

    with allure.step("Check that the server confirmed the deletion"):
        expected_delete_response = {"status": "deleted"}
        assert r_delete.get_json() == expected_delete_response, \
            f"Expected {expected_delete_response}, but received {r_delete.get_json()}"
        allure.attach(
            str(r_delete.get_json()),
            name="Response status",
            attachment_type=allure.attachment_type.JSON
        )

    with allure.step("Send GET request to /api/items to verify the list is empty"):
        list_response = client.get("/api/items")
        list_json = list_response.get_json()

    with allure.step("Check that the list is empty"):
        expected_list = {"items": []}
        assert list_json == expected_list, f"Expected {expected_list}, but received {list_json}"
        allure.attach(
            str(list_json),
            name="Items List After Deletion",
            attachment_type=allure.attachment_type.JSON
        )


@allure.story("Test for checking an attempt to delete a non-existent note")
def test_delete_not_found(client: FlaskClient) -> None:
    """
    Checks an attempt to delete a non-existent note.
    """

    non_existent_id = 999

    with allure.step(f"Send DELETE request to /api/items/{non_existent_id}"):
        r = client.delete(f"/api/items/{non_existent_id}")
        allure.attach(
            str(r.get_json()),
            name="Response JSON",
            attachment_type=allure.attachment_type.JSON
        )

    with allure.step("Check HTTP status code"):
        assert r.status_code == 404, f"Expected code 404, but received {r.status_code}"
        allure.attach(
            str(r.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )

    with allure.step("Check that the server returned the correct error message"):
        expected_error = {"error": "Заметка не найдена"}
        actual_error = r.get_json()
        assert actual_error == expected_error, f"Expected {expected_error}, but received {actual_error}"
        allure.attach(
            str(actual_error),
            name="Response JSON",
            attachment_type=allure.attachment_type.JSON
        )

@pytest.mark.parametrize("payload", [
    {}, {"text": ""}, {"text": "   "}, {"text": 123}, {"text": None}, [],
])

@allure.story("Test for checking for protection against incorrect input")
def test_create_rejects_bad_payload(client: FlaskClient, payload: dict | list) -> None:
    """
    Parameterized test: verifies protection against invalid input.
    """
    
    with allure.step(f"Send POST request with bad payload: {payload}"):
        r = client.post("/api/items", json=payload)
        allure.attach(
            str(payload),
            name="Bad Payload",
            attachment_type=allure.attachment_type.TEXT
        )
        
        allure.attach(
            str(r.get_json()),
            name="Response JSON",
            attachment_type=allure.attachment_type.JSON
        )

    with allure.step("Check HTTP status code"):
        assert r.status_code == 400, f"Expected code 400 for payload {payload}, but received {r.status_code}"
        allure.attach(
            str(r.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )


@allure.story("Test for checking for protection against non-JSON data")
def test_create_rejects_non_json(client: FlaskClient) -> None:
    """
    Checks for protection against non-JSON data.
    """
    
    non_json_data = "text=abc"
    content_type = "application/x-www-form-urlencoded"

    with allure.step("Send POST request with form data instead of JSON"):
        allure.attach(
            f"Data: {non_json_data}\nContent-Type: {content_type}",
            name="Request Details",
            attachment_type=allure.attachment_type.TEXT
        )
        
        r = client.post("/api/items", data=non_json_data, content_type=content_type)
        allure.attach(
            str(r.get_json()),
            name="Response JSON",
            attachment_type=allure.attachment_type.JSON
        )

    with allure.step("Check HTTP status code"):
        assert r.status_code == 400, f"Expected code 400, but received {r.status_code}"
        allure.attach(
            str(r.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )


@allure.story("Test for checking text length limit")
def test_create_rejects_too_long(client: FlaskClient) -> None:
    """
    Checks the text length limit of 200.
    """
    
    long_text = "a" * (MAX_TEXT_LENGTH + 1)

    with allure.step(f"Send POST request with text of length {len(long_text)} (limit is {MAX_TEXT_LENGTH})"):
        allure.attach(
            f"Text length: {len(long_text)}\nMax allowed: {MAX_TEXT_LENGTH}",
            name="Payload Info",
            attachment_type=allure.attachment_type.TEXT
        )
        
        r = client.post("/api/items", json={"text": long_text})
        allure.attach(
            str(r.get_json()),
            name="Response JSON",
            attachment_type=allure.attachment_type.JSON
        )

    with allure.step("Check HTTP status code is 400"):
        assert r.status_code == 400, f"Expected code 400, but received {r.status_code}"
        allure.attach(
            str(r.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )


@allure.story("Test for checking request size limit 16 KB")
def test_body_too_large(client: FlaskClient) -> None:
    """
    Checks the request size limit = 16 KB.
    """
    
    huge_text = "a" * 20000
    approx_size_bytes = len(huge_text) + 15

    with allure.step(f"Send POST request with payload size ~{approx_size_bytes} bytes"):
        allure.attach(
            f"Text length: {len(huge_text)} characters\n"
            f"Approx. payload size: {approx_size_bytes} bytes\n",
            name="Payload Info",
            attachment_type=allure.attachment_type.TEXT
        )
        
        r = client.post("/api/items", json={"text": huge_text})
        allure.attach(
            str(r.get_json()),
            name="Response JSON",
            attachment_type=allure.attachment_type.JSON
        )

    with allure.step("Check HTTP status code"):
        assert r.status_code == 413, f"Expected code 413, but received {r.status_code}"
        allure.attach(
            str(r.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )


@allure.story("Test for checking global error handlers")
def test_not_found_and_method_not_allowed(client: FlaskClient) -> None:
    """
    Checks global error handlers.
    """

    with allure.step("Send GET request to a non-existent URL"):
        r_404 = client.get("/nope")
        allure.attach(
            str(r_404.get_json()),
            name="Response JSON",
            attachment_type=allure.attachment_type.JSON
        )

    with allure.step("Check HTTP status code"):
        assert r_404.status_code == 404, f"Expected code 404 for unknown URL, but received {r_404.status_code}"
        allure.attach(
            str(r_404.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )

    with allure.step("Send DELETE request to /api/items"):
        r_405 = client.delete("/api/items")
        allure.attach(
            str(r_405.get_json()),
            name="Response JSON (405)",
            attachment_type=allure.attachment_type.JSON
        )

    with allure.step("Check HTTP status code"):
        assert r_405.status_code == 405, f"Expected code 405 for DELETE /api/items, but received {r_405.status_code}"
        allure.attach(
            str(r_405.status_code),
            name="Status code",
            attachment_type=allure.attachment_type.TEXT
        )

@allure.story("Test for checking presence of security headers in the response")
def test_security_headers(client: FlaskClient) -> None:
    """
    Checks for the presence of security headers in the response.
    """

    with allure.step("Send GET request to /health and get headers"):
        h = client.get("/health").headers
        allure.attach(
            "\n".join(f"{k}: {v}" for k, v in h.items()),
            name="Response Headers",
            attachment_type=allure.attachment_type.TEXT
        )

    with allure.step("Check X-Content-Type-Options"):
        assert h["X-Content-Type-Options"] == "nosniff"

    with allure.step("Check X-Frame-Options"):
        assert h["X-Frame-Options"] == "DENY"

    with allure.step("Check Content-Security-Policy"):
        csp = h["Content-Security-Policy"]
        assert "default-src 'self'" in csp, f"Missing default-src 'self' in: {csp}"
        assert "frame-ancestors 'none'" in csp, f"Missing frame-ancestors 'none' in: {csp}"

    with allure.step("Check Cache-Control"):
        assert h["Cache-Control"] == "no-store"

    with allure.step("Check Referrer-Policy"):
        assert h["Referrer-Policy"] == "no-referrer"