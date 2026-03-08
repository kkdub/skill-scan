# Test Patterns: pytest Standards for Python 3.13+

## Section 1: Generic Rules

### Assertions

| Rule ID | Severity | Rule |
|---------|----------|------|
| TEST-001 | error | IF asserting HTTP status code THEN use named constant from tests/constants.py |
| TEST-005 | warning | IF comparing float values THEN use pytest.approx() |
| TEST-006 | error | IF testing exception THEN use pytest.raises(SpecificError, match='pattern') |
| TEST-010 | error | IF writing test THEN include at least one assert |

### Mocking

| Rule ID | Severity | Rule |
|---------|----------|------|
| TEST-004 | error | IF mocking external HTTP calls THEN use @respx.mock + respx.get/post().mock() |
| TEST-008 | error | IF isolating code under test THEN mock its dependencies, not itself |

### Naming

| Rule ID | Severity | Rule |
|---------|----------|------|
| TEST-007 | warning | IF naming test function THEN use test_<unit>_<behavior>_<condition> pattern |

### Parametrize

| Rule ID | Severity | Rule |
|---------|----------|------|
| PARAM-001 | info | IF testing same behavior with multiple inputs THEN use @pytest.mark.parametrize |

---

## Section 2: Project-Specific Patterns

## HTTP Status Constants

Use named constants from tests/constants.py instead of magic numbers for HTTP status assertions.

```python
from tests.constants import HTTP_OK
assert response.status_code == HTTP_OK
```

## Exception Assertions

Assert on both exception type and message to catch the right error.

```python
with pytest.raises(ValueError, match="must be positive"):
    process_data(value=-5)
```

**Trap**: pytest.raises(Exception) catches everything -- a different error may slip through undetected.

## HTTP Mocking with respx

Mock external HTTP calls with respx, not unittest.mock.patch.

```python
@respx.mock
async def test_api_client_fetches_data() -> None:
    respx.get("https://api.github.com/search/code").mock(
        return_value=Response(200, json={"items": []})
    )
    result = await search(client)
    assert result.accepted == []
```

## Mock Dependencies

Mock a unit's dependencies, not the unit itself.

```python
def test_search_uses_client(mock_client: MagicMock) -> None:
    service = SearchService(client=mock_client)
    service.search("query")
    mock_client.get.assert_called_once()
```

## Test Names

Follow the pattern test_<unit>_<behavior>_<condition> for self-documenting tests.

```python
def test_scan_detects_prompt_injection_in_skill_md() -> None: ...
def test_verdict_returns_block_when_critical_finding() -> None: ...
```

## Parametrize

Use @pytest.mark.parametrize when testing the same behavior with multiple inputs.

```python
@pytest.mark.parametrize("pattern,expected_severity", [
    ("ignore previous instructions", "critical"),
    ("skip safety checks", "high"),
])
def test_prompt_injection_detection(pattern: str, expected_severity: str) -> None:
    assert detect(pattern).severity == expected_severity
```

## Coverage Strategy

For every public function, write tests covering happy path, edge cases, and error cases.

```
Per public function:
  1. Happy path -- normal inputs, expected behavior
  2. Edge cases -- empty inputs, boundary values
  3. Error cases -- invalid inputs, expected exceptions
```

## Anti-Patterns Summary

Quick lookup of what NOT to do and its correct replacement.

| Anti-Pattern | Correct Pattern | Rule |
|---|---|---|
| assert resp.status_code == 404 | == HTTP_NOT_FOUND | TEST-001 |
| assert result == 3.14 | == pytest.approx(3.14) | TEST-005 |
| pytest.raises(Exception) | pytest.raises(SpecificError, match=...) | TEST-006 |
| def test_user(): | def test_user_returns_none_for_missing_id(): | TEST-007 |
| @patch("myapp.Service.method") | Inject mock via constructor | TEST-008 |
| Test without assertions | Always assert something | TEST-010 |
