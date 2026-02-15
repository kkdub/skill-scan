# Test Patterns: pytest Standards for Python 3.13+

> **Purpose**: Test writing standards for any agent writing or modifying tests.
>
> **Format**: Each pattern follows SITUATION → DECIDE → EXAMPLE → TRAP.

---

## Quick Reference

| Task | Pattern | Rule |
|------|---------|------|
| HTTP status | `assert response.status_code == HTTP_OK` | TEST-001 |
| Float compare | `assert value == pytest.approx(3.14)` | TEST-005 |
| Exception | `with pytest.raises(ValueError, match="msg"):` | TEST-006 |
| Test names | `test_<unit>_<behavior>_<condition>` | TEST-007 |
| Mock target | Mock dependencies, not code under test | TEST-008 |
| Assertions | Every test must assert something | TEST-010 |
| Multiple inputs | `@pytest.mark.parametrize(...)` | PARAM-001 |
| HTTP mocking | `@respx.mock` + `respx.get(url).mock(...)` | TEST-004 |

---

## 1. HTTP Status Constants (TEST-001)

Use named constants from `tests/constants.py`. Never magic numbers.

```python
from tests.constants import HTTP_OK
assert response.status_code == HTTP_OK
```

---

## 2. Exception Assertions (TEST-006)

Use specific type AND match string:

```python
with pytest.raises(ValueError, match="must be positive"):
    process_data(value=-5)
```

**TRAP**: `pytest.raises(Exception)` catches everything — you'll never know if a different error fires.

---

## 3. HTTP Mocking with respx (TEST-004)

Mock HTTP with `respx`, not `unittest.mock.patch`:

```python
@respx.mock
async def test_api_client_fetches_data() -> None:
    respx.get("https://api.github.com/search/code").mock(
        return_value=Response(200, json={"items": []})
    )
    result = await search(client)
    assert result.accepted == []
```

---

## 4. Mock Dependencies, Not Code Under Test (TEST-008)

```python
# CORRECT — mock the dependency
def test_search_uses_client(mock_client: MagicMock) -> None:
    service = SearchService(client=mock_client)
    service.search("query")
    mock_client.get.assert_called_once()

# WRONG — mocking code being tested
@patch("skill_scan.SearchService.search")  # tests the mock, not SearchService
```

---

## 5. Test Names (TEST-007)

Pattern: `test_<unit>_<behavior>_<condition>`

```python
def test_scan_detects_prompt_injection_in_skill_md() -> None: ...
def test_verdict_returns_block_when_critical_finding() -> None: ...
```

---

## 6. Parametrize for Multiple Inputs (PARAM-001)

```python
@pytest.mark.parametrize("pattern,expected_severity", [
    ("ignore previous instructions", "critical"),
    ("skip safety checks", "high"),
])
def test_prompt_injection_detection(pattern: str, expected_severity: str) -> None:
    assert detect(pattern).severity == expected_severity
```

---

## 7. Coverage Strategy

Per public function, test:
1. **Happy path** — normal inputs, expected behavior
2. **Edge cases** — empty inputs, boundary values
3. **Error cases** — invalid inputs, expected exceptions

---

## Anti-Patterns Summary

| Anti-Pattern | Correct Pattern | Rule |
|---|---|---|
| `assert resp.status_code == 404` | `== HTTP_NOT_FOUND` | TEST-001 |
| `assert result == 3.14` | `== pytest.approx(3.14)` | TEST-005 |
| `pytest.raises(Exception)` | `pytest.raises(SpecificError, match=...)` | TEST-006 |
| `def test_user():` | `def test_user_returns_none_for_missing_id():` | TEST-007 |
| `@patch("myapp.Service.method")` | Inject mock via constructor | TEST-008 |
| Test without assertions | Always assert something | TEST-010 |

---

## Related Files

| File | Purpose |
|---|---|
| `.agents/standards/code-rules.json` | Enforceable rules |
| `.agents/standards/CODE-PATTERNS.md` | Design guidance |
| `tests/conftest.py` | Shared fixtures |
| `tests/constants.py` | HTTP status constants |
