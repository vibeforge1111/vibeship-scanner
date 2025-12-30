# Security Scan Report

**Generated:** 2025-12-21 19:11:42 UTC
**Scan ID:** `0dc0b815-0c11-4130-b8fb-e7a2ca4ae2ee`

---

## Repository Information

| Field | Value |
|-------|-------|
| Repository | [erev0s/VAmPI](https://github.com/erev0s/VAmPI) |
| Branch | `main` |
| Scan Date | 2025-12-21 |

---

## Security Score

| Metric | Value |
|--------|-------|
| Score | **0/100** |
| Grade | **F** |
| Status | **danger** |

---

## Severity Breakdown

- **Critical:** 10
- **High:** 31
- **Medium:** 37
- **Info:** 139

**Total Findings:** 217

---

## Findings Summary

| # | Severity | Finding | Location | Scanner |
|---|----------|---------|----------|---------|
| 1 | CRITICAL | Secret Detected: JWT token | `openapi_specs/openapi3.yml:193` | - |
| 2 | CRITICAL | Exposed Secret: Generic Secret Assignment in Config | `api_views/users.py:65` | - |
| 3 | CRITICAL | Exposed Secret: Generic Secret Assignment in Config | `api_views/users.py:68` | - |
| 4 | CRITICAL | Exposed Secret: Generic Secret Assignment in Config | `api_views/users.py:93` | - |
| 5 | CRITICAL | Exposed Secret: Generic Secret Assignment in Config | `api_views/users.py:120` | - |
| 6 | CRITICAL | Exposed Secret: Generic Secret Assignment in Config | `api_views/users.py:189` | - |
| 7 | CRITICAL | Exposed Secret: Generic Secret Assignment in Config | `api_views/users.py:195` | - |
| 8 | CRITICAL | Exposed Secret: Generic Secret Assignment in Config | `models/user_model.py:15` | - |
| 9 | CRITICAL | Exposed Secret: Generic Secret Assignment in Config | `models/user_model.py:24` | - |
| 10 | CRITICAL | Exposed Secret: Generic Secret Assignment in Config | `models/user_model.py:85` | - |
| 11 | HIGH | Password/hash field in response - never expose password data in API | `api_views/json_schemas.py:5` | - |
| 12 | HIGH | Password/hash field in response - never expose password data in API | `api_views/json_schemas.py:15` | - |
| 13 | HIGH | API route returning debug data - may expose sensitive fields | `api_views/users.py:25` | - |
| 14 | HIGH | Debug method exposing sensitive data - remove in production | `api_views/users.py:25` | - |
| 15 | HIGH | Debug endpoint exposing all users with sensitive fields | `api_views/users.py:25` | - |
| 16 | HIGH | Mass assignment - checking for admin flag in user input allows privilege escalation | `api_views/users.py:60` | - |
| 17 | HIGH | Admin flag from user input - mass assignment privilege escalation | `api_views/users.py:61` | - |
| 18 | HIGH | Mass assignment - admin flag from user input allows privilege escalation | `api_views/users.py:61` | - |
| 19 | HIGH | Direct password comparison - use check_password_hash | `api_views/users.py:93` | - |
| 20 | HIGH | Plaintext password comparison - passwords should be hashed | `api_views/users.py:93` | - |
| 21 | HIGH | Plaintext password comparison - passwords should be hashed | `api_views/users.py:102` | - |
| 22 | HIGH | Plaintext password comparison - passwords should be hashed | `api_views/users.py:108` | - |
| 23 | HIGH | BOLA - updating user password by URL username without ownership check | `api_views/users.py:187` | - |
| 24 | HIGH | Database update without authorization check - verify user owns object | `api_views/users.py:194` | - |
| 25 | HIGH | Potential mnemonic seed phrase detected - CRITICAL if real | `app.py:6` | - |
| 26 | HIGH | Flask debug mode enabled - exposes debugger and auto-reloader in production (CWE-489) | `app.py:17` | - |
| 27 | HIGH | Flask/Connexion app running with debug=True - critical security issue in production (CWE-489) | `app.py:17` | - |
| 28 | HIGH | Hardcoded Flask SECRET_KEY - use environment variable | `config.py:13` | - |
| 29 | HIGH | Weak JWT secret - hardcoded short/predictable secret enables token forgery | `config.py:13` | - |
| 30 | HIGH | Weak secret key - use cryptographically secure random value | `config.py:13` | - |
| 31 | HIGH | SQL with unquoted f-string variable - SQL injection risk (CWE-89) | `models/books_model.py:21` | - |
| 32 | HIGH | Storing password without hashing - use generate_password_hash | `models/user_model.py:24` | - |
| 33 | HIGH | Direct password assignment without hashing - use bcrypt.hashpw() or similar (CWE-256) | `models/user_model.py:24` | - |
| 34 | HIGH | Storing password without hashing - always hash passwords with bcrypt (CWE-256) | `models/user_model.py:24` | - |
| 35 | HIGH | Password/hash field in response - never expose password data in API | `models/user_model.py:59` | - |
| 36 | HIGH | Password field included in response dictionary - filter sensitive data (CWE-200) | `models/user_model.py:59` | - |
| 37 | HIGH | Password field in response - never expose passwords in API responses | `models/user_model.py:59` | - |
| 38 | HIGH | SQL injection - f-string with user input in WHERE clause | `models/user_model.py:72` | - |
| 39 | HIGH | SQL injection - f-string in SELECT query with user variable | `models/user_model.py:72` | - |
| 40 | HIGH | SQL SELECT with f-string interpolation - SQL injection vulnerability (CWE-89) | `models/user_model.py:72` | - |
| 41 | HIGH | flask: flask: Possible disclosure of permanent session cookie due to missing Vary: Cookie header | `requirements.txt` | - |
| 42 | MEDIUM | BOLA - object lookup by URL parameter without authorization check | `api_views/books.py:27` | - |
| 43 | MEDIUM | BOLA - object lookup by URL parameter without authorization check | `api_views/books.py:51` | - |
| 44 | MEDIUM | BOLA - accessing book by title without owner verification | `api_views/books.py:51` | - |
| 45 | MEDIUM | BOLA - object lookup by URL parameter without authorization check | `api_views/books.py:62` | - |
| 46 | MEDIUM | Debug function exposed - may leak sensitive data | `api_views/users.py:24` | - |
| 47 | MEDIUM | BOLA - object lookup by URL parameter without authorization check | `api_views/users.py:33` | - |
| 48 | MEDIUM | Specific 'user not found' message enables user enumeration - use generic 'Invalid credentials' (CWE-204) | `api_views/users.py:49` | - |
| 49 | MEDIUM | BOLA - object lookup by URL parameter without authorization check | `api_views/users.py:55` | - |
| 50 | MEDIUM | BOLA - object lookup by URL parameter without authorization check | `api_views/users.py:92` | - |
| 51 | MEDIUM | Direct password comparison - use secrets.compare_digest() for timing-safe comparison (CWE-208) | `api_views/users.py:93` | - |
| 52 | MEDIUM | User enumeration - password error message reveals username exists | `api_views/users.py:103` | - |
| 53 | MEDIUM | User enumeration - error message reveals username does not exist | `api_views/users.py:106` | - |
| 54 | MEDIUM | Empty password/secret string detected (CWE-258) | `api_views/users.py:122` | - |
| 55 | MEDIUM | Empty password/secret string detected (CWE-258) | `api_views/users.py:124` | - |
| 56 | MEDIUM | BOLA - object lookup by URL parameter without authorization check | `api_views/users.py:142` | - |
| 57 | MEDIUM | BOLA - object lookup by URL parameter without authorization check | `api_views/users.py:187` | - |
| 58 | MEDIUM | Object lookup by URL/function parameter - verify authorization | `api_views/users.py:187` | - |
| 59 | MEDIUM | BOLA - object lookup by URL parameter without authorization check | `api_views/users.py:194` | - |
| 60 | MEDIUM | Admin action without audit logging - log privileged operations | `api_views/users.py:206` | - |
| 61 | MEDIUM | BOLA - object lookup by URL parameter without authorization check | `api_views/users.py:211` | - |
| 62 | MEDIUM | Specific 'user not found' message enables user enumeration - use generic 'Invalid credentials' (CWE-204) | `api_views/users.py:220` | - |
| 63 | MEDIUM | Flask running with debug=True - disable in production | `app.py:17` | - |
| 64 | MEDIUM | Binding to 0.0.0.0 exposes service to all network interfaces (CWE-200) | `app.py:17` | - |
| 65 | MEDIUM | App binding to 0.0.0.0 exposes to all network interfaces (CWE-668) | `app.py:17` | - |
| 66 | MEDIUM | Exposing user email/username in response - may enable user enumeration (CWE-200) | `models/books_model.py:24` | - |
| 67 | MEDIUM | Exposing user email/username in response - may enable user enumeration (CWE-200) | `models/user_model.py:28` | - |
| 68 | MEDIUM | Exposing user email/username in response - may enable user enumeration (CWE-200) | `models/user_model.py:56` | - |
| 69 | MEDIUM | Exposing user email/username in response - may enable user enumeration (CWE-200) | `models/user_model.py:59` | - |
| 70 | MEDIUM | SQLAlchemy execute with text - ensure parameterized | `models/user_model.py:73` | - |
| 71 | MEDIUM | SQL injection - executing text query (check for f-string interpolation) | `models/user_model.py:73` | - |
| 72 | MEDIUM | SQLAlchemy text() - ensure parameterized queries | `models/user_model.py:73` | - |
| 73 | MEDIUM | BOLA - object lookup by URL parameter without authorization check | `models/user_model.py:80` | - |
| 74 | MEDIUM | Object lookup by URL/function parameter - verify authorization | `models/user_model.py:80` | - |
| 75 | MEDIUM | random.randrange() is not cryptographically secure - use secrets module (CWE-338) | `models/user_model.py:86` | - |
| 76 | MEDIUM | Admin action without audit logging - log privileged operations | `models/user_model.py:92` | - |
| 77 | MEDIUM | OpenAPI spec has no securitySchemes defined. APIs should require authentication (OWASP API2). | `openapi_specs/openapi3.yml:1` | - |
| 78 | MEDIUM | OpenAPI server URL uses HTTP instead of HTTPS. Use HTTPS for production APIs. | `openapi_specs/openapi3.yml:6` | - |
| 79 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/books.py:14` | - |
| 80 | INFO | Bare except clause - catch specific exceptions | `api_views/books.py:19` | - |
| 81 | INFO | Bare except catches all exceptions including KeyboardInterrupt - be specific (CWE-396) | `api_views/books.py:21` | - |
| 82 | INFO | Response without Content-Security-Policy header | `api_views/books.py:22` | - |
| 83 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/books.py:22` | - |
| 84 | INFO | Response without Content-Security-Policy header | `api_views/books.py:25` | - |
| 85 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/books.py:25` | - |
| 86 | INFO | Response without Content-Security-Policy header | `api_views/books.py:32` | - |
| 87 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/books.py:32` | - |
| 88 | INFO | session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754) | `api_views/books.py:37` | - |
| 89 | INFO | Response without Content-Security-Policy header | `api_views/books.py:42` | - |
| 90 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/books.py:42` | - |
| 91 | INFO | Response without Content-Security-Policy header | `api_views/books.py:48` | - |
| 92 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/books.py:48` | - |
| 93 | INFO | Response without Content-Security-Policy header | `api_views/books.py:58` | - |
| 94 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/books.py:58` | - |
| 95 | INFO | Response without Content-Security-Policy header | `api_views/books.py:60` | - |
| 96 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/books.py:60` | - |
| 97 | INFO | Response without Content-Security-Policy header | `api_views/books.py:70` | - |
| 98 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/books.py:70` | - |
| 99 | INFO | Response without Content-Security-Policy header | `api_views/books.py:72` | - |
| 100 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/books.py:72` | - |
| 101 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/main.py:12` | - |
| 102 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/main.py:19` | - |
| 103 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:14` | - |
| 104 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:16` | - |
| 105 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:21` | - |
| 106 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:26` | - |
| 107 | INFO | Response without Content-Security-Policy header | `api_views/users.py:31` | - |
| 108 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:31` | - |
| 109 | INFO | Response without Content-Security-Policy header | `api_views/users.py:42` | - |
| 110 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:42` | - |
| 111 | INFO | Response without Content-Security-Policy header | `api_views/users.py:47` | - |
| 112 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:47` | - |
| 113 | INFO | Response without Content-Security-Policy header | `api_views/users.py:49` | - |
| 114 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:49` | - |
| 115 | INFO | User lookup pattern - ensure same error message for user not found and wrong password (CWE-204) | `api_views/users.py:55` | - |
| 116 | INFO | session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754) | `api_views/users.py:71` | - |
| 117 | INFO | Response without Content-Security-Policy header | `api_views/users.py:78` | - |
| 118 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:78` | - |
| 119 | INFO | Response without Content-Security-Policy header | `api_views/users.py:80` | - |
| 120 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:80` | - |
| 121 | INFO | Response without Content-Security-Policy header | `api_views/users.py:82` | - |
| 122 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:82` | - |
| 123 | INFO | Bare except clause - catch specific exceptions | `api_views/users.py:88` | - |
| 124 | INFO | User lookup pattern - ensure same error message for user not found and wrong password (CWE-204) | `api_views/users.py:92` | - |
| 125 | INFO | Sensitive data access - consider audit logging for compliance | `api_views/users.py:93` | - |
| 126 | INFO | Response without Content-Security-Policy header | `api_views/users.py:100` | - |
| 127 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:100` | - |
| 128 | INFO | Sensitive data access - consider audit logging for compliance | `api_views/users.py:102` | - |
| 129 | INFO | Response without Content-Security-Policy header | `api_views/users.py:103` | - |
| 130 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:103` | - |
| 131 | INFO | Response without Content-Security-Policy header | `api_views/users.py:106` | - |
| 132 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:106` | - |
| 133 | INFO | Sensitive data access - consider audit logging for compliance | `api_views/users.py:108` | - |
| 134 | INFO | Response without Content-Security-Policy header | `api_views/users.py:109` | - |
| 135 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:109` | - |
| 136 | INFO | Response without Content-Security-Policy header | `api_views/users.py:112` | - |
| 137 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:112` | - |
| 138 | INFO | Bare except catches all exceptions including KeyboardInterrupt - be specific (CWE-396) | `api_views/users.py:113` | - |
| 139 | INFO | Response without Content-Security-Policy header | `api_views/users.py:114` | - |
| 140 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:114` | - |
| 141 | INFO | Bare except clause - catch specific exceptions | `api_views/users.py:119` | - |
| 142 | INFO | Compiled regex split - ensure pattern is not vulnerable to ReDoS | `api_views/users.py:120` | - |
| 143 | INFO | Bare except catches all exceptions including KeyboardInterrupt - be specific (CWE-396) | `api_views/users.py:121` | - |
| 144 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:127` | - |
| 145 | INFO | FastAPI endpoint returning dict - consider using response_model for schema validation | `api_views/users.py:129` | - |
| 146 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:129` | - |
| 147 | INFO | Bare except clause - catch specific exceptions | `api_views/users.py:134` | - |
| 148 | INFO | Bare except catches all exceptions including KeyboardInterrupt - be specific (CWE-396) | `api_views/users.py:136` | - |
| 149 | INFO | Response without Content-Security-Policy header | `api_views/users.py:137` | - |
| 150 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:137` | - |
| 151 | INFO | Response without Content-Security-Policy header | `api_views/users.py:140` | - |
| 152 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:140` | - |
| 153 | INFO | Regex search - ensure pattern is not vulnerable to ReDoS (CWE-1333) | `api_views/users.py:144` | - |
| 154 | INFO | session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754) | `api_views/users.py:149` | - |
| 155 | INFO | Response without Content-Security-Policy header | `api_views/users.py:157` | - |
| 156 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:157` | - |
| 157 | INFO | Response without Content-Security-Policy header | `api_views/users.py:159` | - |
| 158 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:159` | - |
| 159 | INFO | Regex search - ensure pattern is not vulnerable to ReDoS (CWE-1333) | `api_views/users.py:163` | - |
| 160 | INFO | session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754) | `api_views/users.py:165` | - |
| 161 | INFO | Response without Content-Security-Policy header | `api_views/users.py:173` | - |
| 162 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:173` | - |
| 163 | INFO | Response without Content-Security-Policy header | `api_views/users.py:175` | - |
| 164 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:175` | - |
| 165 | INFO | Response without Content-Security-Policy header | `api_views/users.py:183` | - |
| 166 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:183` | - |
| 167 | INFO | User lookup pattern - ensure same error message for user not found and wrong password (CWE-204) | `api_views/users.py:187` | - |
| 168 | INFO | Sensitive data access - consider audit logging for compliance | `api_views/users.py:189` | - |
| 169 | INFO | session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754) | `api_views/users.py:190` | - |
| 170 | INFO | Response without Content-Security-Policy header | `api_views/users.py:192` | - |
| 171 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:192` | - |
| 172 | INFO | Sensitive data access - consider audit logging for compliance | `api_views/users.py:195` | - |
| 173 | INFO | session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754) | `api_views/users.py:196` | - |
| 174 | INFO | Response without Content-Security-Policy header | `api_views/users.py:201` | - |
| 175 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:201` | - |
| 176 | INFO | Response without Content-Security-Policy header | `api_views/users.py:203` | - |
| 177 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:203` | - |
| 178 | INFO | Response without Content-Security-Policy header | `api_views/users.py:209` | - |
| 179 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:209` | - |
| 180 | INFO | User lookup pattern - ensure same error message for user not found and wrong password (CWE-204) | `api_views/users.py:211` | - |
| 181 | INFO | Response without Content-Security-Policy header | `api_views/users.py:218` | - |
| 182 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:218` | - |
| 183 | INFO | Response without Content-Security-Policy header | `api_views/users.py:220` | - |
| 184 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:220` | - |
| 185 | INFO | Response without Content-Security-Policy header | `api_views/users.py:222` | - |
| 186 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `api_views/users.py:222` | - |
| 187 | INFO | Debug mode may be enabled - ensure disabled in production | `app.py:17` | - |
| 188 | INFO | SQLite database file - ensure not web-accessible and properly backed up (CWE-219) | `config.py:9` | - |
| 189 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `config.py:24` | - |
| 190 | INFO | Function accepts user_id parameter - ensure authorization check before accessing user resources (CWE-639) | `models/books_model.py:15` | - |
| 191 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/books_model.py:21` | - |
| 192 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/books_model.py:24` | - |
| 193 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/books_model.py:28` | - |
| 194 | INFO | Password in constructor - consider adding password strength validation (CWE-521) | `models/user_model.py:21` | - |
| 195 | INFO | Sensitive data access - consider audit logging for compliance | `models/user_model.py:24` | - |
| 196 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/user_model.py:28` | - |
| 197 | INFO | Function accepts user_id parameter - ensure authorization check before accessing user resources (CWE-639) | `models/user_model.py:30` | - |
| 198 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/user_model.py:37` | - |
| 199 | INFO | JWT encoding - ensure secret key is not weak/hardcoded | `models/user_model.py:37` | - |
| 200 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/user_model.py:43` | - |
| 201 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/user_model.py:49` | - |
| 202 | INFO | FastAPI endpoint returning dict - consider using response_model for schema validation | `models/user_model.py:51` | - |
| 203 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/user_model.py:51` | - |
| 204 | INFO | FastAPI endpoint returning dict - consider using response_model for schema validation | `models/user_model.py:53` | - |
| 205 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/user_model.py:53` | - |
| 206 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/user_model.py:56` | - |
| 207 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/user_model.py:59` | - |
| 208 | INFO | Sensitive data access - consider audit logging for compliance | `models/user_model.py:59` | - |
| 209 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/user_model.py:63` | - |
| 210 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/user_model.py:67` | - |
| 211 | INFO | CTF flag in response - this indicates an intentional vulnerability for testing | `models/user_model.py:71` | - |
| 212 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/user_model.py:81` | - |
| 213 | INFO | session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754) | `models/user_model.py:89` | - |
| 214 | INFO | session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754) | `models/user_model.py:94` | - |
| 215 | INFO | Returning item directly - verify user has access to this item before returning (CWE-285) | `models/user_model.py:95` | - |
| 216 | INFO | OpenAPI spec - consider documenting rate limiting with x-ratelimit extension (OWASP API4). | `openapi_specs/openapi3.yml:1` | - |
| 217 | INFO | OpenAPI paths without security requirement. Endpoints may be unauthenticated (OWASP API2). | `openapi_specs/openapi3.yml:15` | - |

---

## Detailed Findings

### 1. [CRITICAL] Secret Detected: JWT token

- **Location:** `openapi_specs/openapi3.yml:193`
- **Rule ID:** trivy-secret-jwt-token
- **Scanner:** N/A

**Description:** No description available

### 2. [CRITICAL] Exposed Secret: Generic Secret Assignment in Config

- **Location:** `api_views/users.py:65`
- **Rule ID:** gitleaks-generic-secret-assignment
- **Scanner:** N/A

**Description:** No description available

### 3. [CRITICAL] Exposed Secret: Generic Secret Assignment in Config

- **Location:** `api_views/users.py:68`
- **Rule ID:** gitleaks-generic-secret-assignment
- **Scanner:** N/A

**Description:** No description available

### 4. [CRITICAL] Exposed Secret: Generic Secret Assignment in Config

- **Location:** `api_views/users.py:93`
- **Rule ID:** gitleaks-generic-secret-assignment
- **Scanner:** N/A

**Description:** No description available

### 5. [CRITICAL] Exposed Secret: Generic Secret Assignment in Config

- **Location:** `api_views/users.py:120`
- **Rule ID:** gitleaks-generic-secret-assignment
- **Scanner:** N/A

**Description:** No description available

### 6. [CRITICAL] Exposed Secret: Generic Secret Assignment in Config

- **Location:** `api_views/users.py:189`
- **Rule ID:** gitleaks-generic-secret-assignment
- **Scanner:** N/A

**Description:** No description available

### 7. [CRITICAL] Exposed Secret: Generic Secret Assignment in Config

- **Location:** `api_views/users.py:195`
- **Rule ID:** gitleaks-generic-secret-assignment
- **Scanner:** N/A

**Description:** No description available

### 8. [CRITICAL] Exposed Secret: Generic Secret Assignment in Config

- **Location:** `models/user_model.py:15`
- **Rule ID:** gitleaks-generic-secret-assignment
- **Scanner:** N/A

**Description:** No description available

### 9. [CRITICAL] Exposed Secret: Generic Secret Assignment in Config

- **Location:** `models/user_model.py:24`
- **Rule ID:** gitleaks-generic-secret-assignment
- **Scanner:** N/A

**Description:** No description available

### 10. [CRITICAL] Exposed Secret: Generic Secret Assignment in Config

- **Location:** `models/user_model.py:85`
- **Rule ID:** gitleaks-generic-secret-assignment
- **Scanner:** N/A

**Description:** No description available

### 11. [HIGH] Password/hash field in response - never expose password data in API

- **Location:** `api_views/json_schemas.py:5`
- **Rule ID:** rules.py-data-exposure-password-hash
- **Scanner:** N/A

**Description:** No description available

### 12. [HIGH] Password/hash field in response - never expose password data in API

- **Location:** `api_views/json_schemas.py:15`
- **Rule ID:** rules.py-data-exposure-password-hash
- **Scanner:** N/A

**Description:** No description available

### 13. [HIGH] API route returning debug data - may expose sensitive fields

- **Location:** `api_views/users.py:25`
- **Rule ID:** rules.py-route-returns-debug
- **Scanner:** N/A

**Description:** No description available

### 14. [HIGH] Debug method exposing sensitive data - remove in production

- **Location:** `api_views/users.py:25`
- **Rule ID:** rules.py-debug-method-call
- **Scanner:** N/A

**Description:** No description available

### 15. [HIGH] Debug endpoint exposing all users with sensitive fields

- **Location:** `api_views/users.py:25`
- **Rule ID:** rules.py-vampi-debug-all-users
- **Scanner:** N/A

**Description:** No description available

### 16. [HIGH] Mass assignment - checking for admin flag in user input allows privilege escalation

- **Location:** `api_views/users.py:60`
- **Rule ID:** rules.py-vampi-mass-assign-admin-check
- **Scanner:** N/A

**Description:** No description available

### 17. [HIGH] Admin flag from user input - mass assignment privilege escalation

- **Location:** `api_views/users.py:61`
- **Rule ID:** rules.py-mass-assignment-admin
- **Scanner:** N/A

**Description:** No description available

### 18. [HIGH] Mass assignment - admin flag from user input allows privilege escalation

- **Location:** `api_views/users.py:61`
- **Rule ID:** rules.py-vampi-mass-assign-admin-value
- **Scanner:** N/A

**Description:** No description available

### 19. [HIGH] Direct password comparison - use check_password_hash

- **Location:** `api_views/users.py:93`
- **Rule ID:** rules.py-direct-password-equality
- **Scanner:** N/A

**Description:** No description available

### 20. [HIGH] Plaintext password comparison - passwords should be hashed

- **Location:** `api_views/users.py:93`
- **Rule ID:** rules.py-vampi-plaintext-password
- **Scanner:** N/A

**Description:** No description available

### 21. [HIGH] Plaintext password comparison - passwords should be hashed

- **Location:** `api_views/users.py:102`
- **Rule ID:** rules.py-vampi-plaintext-password-ne
- **Scanner:** N/A

**Description:** No description available

### 22. [HIGH] Plaintext password comparison - passwords should be hashed

- **Location:** `api_views/users.py:108`
- **Rule ID:** rules.py-vampi-plaintext-password-ne
- **Scanner:** N/A

**Description:** No description available

### 23. [HIGH] BOLA - updating user password by URL username without ownership check

- **Location:** `api_views/users.py:187`
- **Rule ID:** rules.py-vampi-bola-password-update
- **Scanner:** N/A

**Description:** No description available

### 24. [HIGH] Database update without authorization check - verify user owns object

- **Location:** `api_views/users.py:194`
- **Rule ID:** rules.py-update-without-auth-check
- **Scanner:** N/A

**Description:** No description available

### 25. [HIGH] Potential mnemonic seed phrase detected - CRITICAL if real

- **Location:** `app.py:6`
- **Rule ID:** rules._shared.shared-mnemonic-phrase
- **Scanner:** N/A

**Description:** No description available

### 26. [HIGH] Flask debug mode enabled - exposes debugger and auto-reloader in production (CWE-489)

- **Location:** `app.py:17`
- **Rule ID:** rules.py-flask-debug-true
- **Scanner:** N/A

**Description:** No description available

### 27. [HIGH] Flask/Connexion app running with debug=True - critical security issue in production (CWE-489)

- **Location:** `app.py:17`
- **Rule ID:** rules.py-flask-debug-run-args
- **Scanner:** N/A

**Description:** No description available

### 28. [HIGH] Hardcoded Flask SECRET_KEY - use environment variable

- **Location:** `config.py:13`
- **Rule ID:** rules.py-flask-config-secret-key
- **Scanner:** N/A

**Description:** No description available

### 29. [HIGH] Weak JWT secret - hardcoded short/predictable secret enables token forgery

- **Location:** `config.py:13`
- **Rule ID:** rules.py-vampi-weak-jwt-secret
- **Scanner:** N/A

**Description:** No description available

### 30. [HIGH] Weak secret key - use cryptographically secure random value

- **Location:** `config.py:13`
- **Rule ID:** rules.py-weak-secret-string
- **Scanner:** N/A

**Description:** No description available

### 31. [HIGH] SQL with unquoted f-string variable - SQL injection risk (CWE-89)

- **Location:** `models/books_model.py:21`
- **Rule ID:** rules.py-sql-fstring-unquoted
- **Scanner:** N/A

**Description:** No description available

### 32. [HIGH] Storing password without hashing - use generate_password_hash

- **Location:** `models/user_model.py:24`
- **Rule ID:** rules.py-model-password-plaintext
- **Scanner:** N/A

**Description:** No description available

### 33. [HIGH] Direct password assignment without hashing - use bcrypt.hashpw() or similar (CWE-256)

- **Location:** `models/user_model.py:24`
- **Rule ID:** rules.py-password-plaintext-assignment
- **Scanner:** N/A

**Description:** No description available

### 34. [HIGH] Storing password without hashing - always hash passwords with bcrypt (CWE-256)

- **Location:** `models/user_model.py:24`
- **Rule ID:** rules.py-password-store-plaintext
- **Scanner:** N/A

**Description:** No description available

### 35. [HIGH] Password/hash field in response - never expose password data in API

- **Location:** `models/user_model.py:59`
- **Rule ID:** rules.py-data-exposure-password-hash
- **Scanner:** N/A

**Description:** No description available

### 36. [HIGH] Password field included in response dictionary - filter sensitive data (CWE-200)

- **Location:** `models/user_model.py:59`
- **Rule ID:** rules.py-password-in-dict-response
- **Scanner:** N/A

**Description:** No description available

### 37. [HIGH] Password field in response - never expose passwords in API responses

- **Location:** `models/user_model.py:59`
- **Rule ID:** rules.py-password-in-json-response
- **Scanner:** N/A

**Description:** No description available

### 38. [HIGH] SQL injection - f-string with user input in WHERE clause

- **Location:** `models/user_model.py:72`
- **Rule ID:** rules.py-vampi-sqli-fstring
- **Scanner:** N/A

**Description:** No description available

### 39. [HIGH] SQL injection - f-string in SELECT query with user variable

- **Location:** `models/user_model.py:72`
- **Rule ID:** rules.py-sqli-fstring-select
- **Scanner:** N/A

**Description:** No description available

### 40. [HIGH] SQL SELECT with f-string interpolation - SQL injection vulnerability (CWE-89)

- **Location:** `models/user_model.py:72`
- **Rule ID:** rules.py-sql-fstring-select-double
- **Scanner:** N/A

**Description:** No description available

### 41. [HIGH] flask: flask: Possible disclosure of permanent session cookie due to missing Vary: Cookie header

- **Location:** `requirements.txt`
- **Rule ID:** trivy-CVE-2023-30861
- **Scanner:** N/A

**Description:** No description available

### 42. [MEDIUM] BOLA - object lookup by URL parameter without authorization check

- **Location:** `api_views/books.py:27`
- **Rule ID:** rules.py-bola-query-url-param
- **Scanner:** N/A

**Description:** No description available

### 43. [MEDIUM] BOLA - object lookup by URL parameter without authorization check

- **Location:** `api_views/books.py:51`
- **Rule ID:** rules.py-bola-query-url-param
- **Scanner:** N/A

**Description:** No description available

### 44. [MEDIUM] BOLA - accessing book by title without owner verification

- **Location:** `api_views/books.py:51`
- **Rule ID:** rules.py-vampi-bola-book-access
- **Scanner:** N/A

**Description:** No description available

### 45. [MEDIUM] BOLA - object lookup by URL parameter without authorization check

- **Location:** `api_views/books.py:62`
- **Rule ID:** rules.py-bola-query-url-param
- **Scanner:** N/A

**Description:** No description available

### 46. [MEDIUM] Debug function exposed - may leak sensitive data

- **Location:** `api_views/users.py:24`
- **Rule ID:** rules.py-vampi-debug-endpoint
- **Scanner:** N/A

**Description:** No description available

### 47. [MEDIUM] BOLA - object lookup by URL parameter without authorization check

- **Location:** `api_views/users.py:33`
- **Rule ID:** rules.py-bola-query-url-param
- **Scanner:** N/A

**Description:** No description available

### 48. [MEDIUM] Specific 'user not found' message enables user enumeration - use generic 'Invalid credentials' (CWE-204)

- **Location:** `api_views/users.py:49`
- **Rule ID:** rules.py-user-enumeration-message
- **Scanner:** N/A

**Description:** No description available

### 49. [MEDIUM] BOLA - object lookup by URL parameter without authorization check

- **Location:** `api_views/users.py:55`
- **Rule ID:** rules.py-bola-query-url-param
- **Scanner:** N/A

**Description:** No description available

### 50. [MEDIUM] BOLA - object lookup by URL parameter without authorization check

- **Location:** `api_views/users.py:92`
- **Rule ID:** rules.py-bola-query-url-param
- **Scanner:** N/A

**Description:** No description available

### 51. [MEDIUM] Direct password comparison - use secrets.compare_digest() for timing-safe comparison (CWE-208)

- **Location:** `api_views/users.py:93`
- **Rule ID:** rules.py-auth-password-direct-compare
- **Scanner:** N/A

**Description:** No description available

### 52. [MEDIUM] User enumeration - password error message reveals username exists

- **Location:** `api_views/users.py:103`
- **Rule ID:** rules.py-vampi-user-enum-password-error
- **Scanner:** N/A

**Description:** No description available

### 53. [MEDIUM] User enumeration - error message reveals username does not exist

- **Location:** `api_views/users.py:106`
- **Rule ID:** rules.py-vampi-user-enum-username-error
- **Scanner:** N/A

**Description:** No description available

### 54. [MEDIUM] Empty password/secret string detected (CWE-258)

- **Location:** `api_views/users.py:122`
- **Rule ID:** rules.py-empty-password
- **Scanner:** N/A

**Description:** No description available

### 55. [MEDIUM] Empty password/secret string detected (CWE-258)

- **Location:** `api_views/users.py:124`
- **Rule ID:** rules.py-empty-password
- **Scanner:** N/A

**Description:** No description available

### 56. [MEDIUM] BOLA - object lookup by URL parameter without authorization check

- **Location:** `api_views/users.py:142`
- **Rule ID:** rules.py-bola-query-url-param
- **Scanner:** N/A

**Description:** No description available

### 57. [MEDIUM] BOLA - object lookup by URL parameter without authorization check

- **Location:** `api_views/users.py:187`
- **Rule ID:** rules.py-bola-query-url-param
- **Scanner:** N/A

**Description:** No description available

### 58. [MEDIUM] Object lookup by URL/function parameter - verify authorization

- **Location:** `api_views/users.py:187`
- **Rule ID:** rules.py-idor-url-param-lookup
- **Scanner:** N/A

**Description:** No description available

### 59. [MEDIUM] BOLA - object lookup by URL parameter without authorization check

- **Location:** `api_views/users.py:194`
- **Rule ID:** rules.py-bola-query-url-param
- **Scanner:** N/A

**Description:** No description available

### 60. [MEDIUM] Admin action without audit logging - log privileged operations

- **Location:** `api_views/users.py:206`
- **Rule ID:** rules.py-admin-action-no-log
- **Scanner:** N/A

**Description:** No description available

### 61. [MEDIUM] BOLA - object lookup by URL parameter without authorization check

- **Location:** `api_views/users.py:211`
- **Rule ID:** rules.py-bola-query-url-param
- **Scanner:** N/A

**Description:** No description available

### 62. [MEDIUM] Specific 'user not found' message enables user enumeration - use generic 'Invalid credentials' (CWE-204)

- **Location:** `api_views/users.py:220`
- **Rule ID:** rules.py-user-enumeration-message
- **Scanner:** N/A

**Description:** No description available

### 63. [MEDIUM] Flask running with debug=True - disable in production

- **Location:** `app.py:17`
- **Rule ID:** rules.py-vampi-flask-debug
- **Scanner:** N/A

**Description:** No description available

### 64. [MEDIUM] Binding to 0.0.0.0 exposes service to all network interfaces (CWE-200)

- **Location:** `app.py:17`
- **Rule ID:** rules.py-bind-all-interfaces
- **Scanner:** N/A

**Description:** No description available

### 65. [MEDIUM] App binding to 0.0.0.0 exposes to all network interfaces (CWE-668)

- **Location:** `app.py:17`
- **Rule ID:** rules.py-flask-bind-all-interfaces
- **Scanner:** N/A

**Description:** No description available

### 66. [MEDIUM] Exposing user email/username in response - may enable user enumeration (CWE-200)

- **Location:** `models/books_model.py:24`
- **Rule ID:** rules.py-user-email-exposure
- **Scanner:** N/A

**Description:** No description available

### 67. [MEDIUM] Exposing user email/username in response - may enable user enumeration (CWE-200)

- **Location:** `models/user_model.py:28`
- **Rule ID:** rules.py-user-email-exposure
- **Scanner:** N/A

**Description:** No description available

### 68. [MEDIUM] Exposing user email/username in response - may enable user enumeration (CWE-200)

- **Location:** `models/user_model.py:56`
- **Rule ID:** rules.py-user-email-exposure
- **Scanner:** N/A

**Description:** No description available

### 69. [MEDIUM] Exposing user email/username in response - may enable user enumeration (CWE-200)

- **Location:** `models/user_model.py:59`
- **Rule ID:** rules.py-user-email-exposure
- **Scanner:** N/A

**Description:** No description available

### 70. [MEDIUM] SQLAlchemy execute with text - ensure parameterized

- **Location:** `models/user_model.py:73`
- **Rule ID:** rules.py-sqlalchemy-execute-text
- **Scanner:** N/A

**Description:** No description available

### 71. [MEDIUM] SQL injection - executing text query (check for f-string interpolation)

- **Location:** `models/user_model.py:73`
- **Rule ID:** rules.py-vampi-sqli-text-execute
- **Scanner:** N/A

**Description:** No description available

### 72. [MEDIUM] SQLAlchemy text() - ensure parameterized queries

- **Location:** `models/user_model.py:73`
- **Rule ID:** rules.py-sqlalchemy-text
- **Scanner:** N/A

**Description:** No description available

### 73. [MEDIUM] BOLA - object lookup by URL parameter without authorization check

- **Location:** `models/user_model.py:80`
- **Rule ID:** rules.py-bola-query-url-param
- **Scanner:** N/A

**Description:** No description available

### 74. [MEDIUM] Object lookup by URL/function parameter - verify authorization

- **Location:** `models/user_model.py:80`
- **Rule ID:** rules.py-idor-url-param-lookup
- **Scanner:** N/A

**Description:** No description available

### 75. [MEDIUM] random.randrange() is not cryptographically secure - use secrets module (CWE-338)

- **Location:** `models/user_model.py:86`
- **Rule ID:** rules.py-random-randrange
- **Scanner:** N/A

**Description:** No description available

### 76. [MEDIUM] Admin action without audit logging - log privileged operations

- **Location:** `models/user_model.py:92`
- **Rule ID:** rules.py-admin-action-no-log
- **Scanner:** N/A

**Description:** No description available

### 77. [MEDIUM] OpenAPI spec has no securitySchemes defined. APIs should require authentication (OWASP API2).

- **Location:** `openapi_specs/openapi3.yml:1`
- **Rule ID:** rules.openapi-no-security-schemes
- **Scanner:** N/A

**Description:** No description available

### 78. [MEDIUM] OpenAPI server URL uses HTTP instead of HTTPS. Use HTTPS for production APIs.

- **Location:** `openapi_specs/openapi3.yml:6`
- **Rule ID:** rules.openapi-server-http
- **Scanner:** N/A

**Description:** No description available

### 79. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/books.py:14`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 80. [INFO] Bare except clause - catch specific exceptions

- **Location:** `api_views/books.py:19`
- **Rule ID:** rules.py-bare-except
- **Scanner:** N/A

**Description:** No description available

### 81. [INFO] Bare except catches all exceptions including KeyboardInterrupt - be specific (CWE-396)

- **Location:** `api_views/books.py:21`
- **Rule ID:** rules.py-bare-exception
- **Scanner:** N/A

**Description:** No description available

### 82. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/books.py:22`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 83. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/books.py:22`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 84. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/books.py:25`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 85. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/books.py:25`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 86. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/books.py:32`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 87. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/books.py:32`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 88. [INFO] session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754)

- **Location:** `api_views/books.py:37`
- **Rule ID:** rules.py-sqlalchemy-commit-no-except
- **Scanner:** N/A

**Description:** No description available

### 89. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/books.py:42`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 90. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/books.py:42`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 91. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/books.py:48`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 92. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/books.py:48`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 93. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/books.py:58`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 94. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/books.py:58`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 95. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/books.py:60`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 96. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/books.py:60`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 97. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/books.py:70`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 98. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/books.py:70`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 99. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/books.py:72`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 100. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/books.py:72`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 101. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/main.py:12`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 102. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/main.py:19`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 103. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:14`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 104. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:16`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 105. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:21`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 106. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:26`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 107. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:31`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 108. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:31`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 109. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:42`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 110. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:42`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 111. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:47`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 112. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:47`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 113. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:49`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 114. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:49`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 115. [INFO] User lookup pattern - ensure same error message for user not found and wrong password (CWE-204)

- **Location:** `api_views/users.py:55`
- **Rule ID:** rules.py-user-query-enumeration
- **Scanner:** N/A

**Description:** No description available

### 116. [INFO] session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754)

- **Location:** `api_views/users.py:71`
- **Rule ID:** rules.py-sqlalchemy-commit-no-except
- **Scanner:** N/A

**Description:** No description available

### 117. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:78`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 118. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:78`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 119. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:80`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 120. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:80`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 121. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:82`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 122. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:82`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 123. [INFO] Bare except clause - catch specific exceptions

- **Location:** `api_views/users.py:88`
- **Rule ID:** rules.py-bare-except
- **Scanner:** N/A

**Description:** No description available

### 124. [INFO] User lookup pattern - ensure same error message for user not found and wrong password (CWE-204)

- **Location:** `api_views/users.py:92`
- **Rule ID:** rules.py-user-query-enumeration
- **Scanner:** N/A

**Description:** No description available

### 125. [INFO] Sensitive data access - consider audit logging for compliance

- **Location:** `api_views/users.py:93`
- **Rule ID:** rules.py-sensitive-access-no-log
- **Scanner:** N/A

**Description:** No description available

### 126. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:100`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 127. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:100`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 128. [INFO] Sensitive data access - consider audit logging for compliance

- **Location:** `api_views/users.py:102`
- **Rule ID:** rules.py-sensitive-access-no-log
- **Scanner:** N/A

**Description:** No description available

### 129. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:103`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 130. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:103`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 131. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:106`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 132. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:106`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 133. [INFO] Sensitive data access - consider audit logging for compliance

- **Location:** `api_views/users.py:108`
- **Rule ID:** rules.py-sensitive-access-no-log
- **Scanner:** N/A

**Description:** No description available

### 134. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:109`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 135. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:109`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 136. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:112`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 137. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:112`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 138. [INFO] Bare except catches all exceptions including KeyboardInterrupt - be specific (CWE-396)

- **Location:** `api_views/users.py:113`
- **Rule ID:** rules.py-bare-exception
- **Scanner:** N/A

**Description:** No description available

### 139. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:114`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 140. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:114`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 141. [INFO] Bare except clause - catch specific exceptions

- **Location:** `api_views/users.py:119`
- **Rule ID:** rules.py-bare-except
- **Scanner:** N/A

**Description:** No description available

### 142. [INFO] Compiled regex split - ensure pattern is not vulnerable to ReDoS

- **Location:** `api_views/users.py:120`
- **Rule ID:** rules.py-redos-compiled-split
- **Scanner:** N/A

**Description:** No description available

### 143. [INFO] Bare except catches all exceptions including KeyboardInterrupt - be specific (CWE-396)

- **Location:** `api_views/users.py:121`
- **Rule ID:** rules.py-bare-exception
- **Scanner:** N/A

**Description:** No description available

### 144. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:127`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 145. [INFO] FastAPI endpoint returning dict - consider using response_model for schema validation

- **Location:** `api_views/users.py:129`
- **Rule ID:** rules.py-fastapi-return-dict
- **Scanner:** N/A

**Description:** No description available

### 146. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:129`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 147. [INFO] Bare except clause - catch specific exceptions

- **Location:** `api_views/users.py:134`
- **Rule ID:** rules.py-bare-except
- **Scanner:** N/A

**Description:** No description available

### 148. [INFO] Bare except catches all exceptions including KeyboardInterrupt - be specific (CWE-396)

- **Location:** `api_views/users.py:136`
- **Rule ID:** rules.py-bare-exception
- **Scanner:** N/A

**Description:** No description available

### 149. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:137`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 150. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:137`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 151. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:140`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 152. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:140`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 153. [INFO] Regex search - ensure pattern is not vulnerable to ReDoS (CWE-1333)

- **Location:** `api_views/users.py:144`
- **Rule ID:** rules.py-redos-re-search
- **Scanner:** N/A

**Description:** No description available

### 154. [INFO] session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754)

- **Location:** `api_views/users.py:149`
- **Rule ID:** rules.py-sqlalchemy-commit-no-except
- **Scanner:** N/A

**Description:** No description available

### 155. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:157`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 156. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:157`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 157. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:159`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 158. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:159`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 159. [INFO] Regex search - ensure pattern is not vulnerable to ReDoS (CWE-1333)

- **Location:** `api_views/users.py:163`
- **Rule ID:** rules.py-redos-re-search
- **Scanner:** N/A

**Description:** No description available

### 160. [INFO] session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754)

- **Location:** `api_views/users.py:165`
- **Rule ID:** rules.py-sqlalchemy-commit-no-except
- **Scanner:** N/A

**Description:** No description available

### 161. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:173`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 162. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:173`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 163. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:175`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 164. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:175`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 165. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:183`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 166. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:183`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 167. [INFO] User lookup pattern - ensure same error message for user not found and wrong password (CWE-204)

- **Location:** `api_views/users.py:187`
- **Rule ID:** rules.py-user-query-enumeration
- **Scanner:** N/A

**Description:** No description available

### 168. [INFO] Sensitive data access - consider audit logging for compliance

- **Location:** `api_views/users.py:189`
- **Rule ID:** rules.py-sensitive-access-no-log
- **Scanner:** N/A

**Description:** No description available

### 169. [INFO] session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754)

- **Location:** `api_views/users.py:190`
- **Rule ID:** rules.py-sqlalchemy-commit-no-except
- **Scanner:** N/A

**Description:** No description available

### 170. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:192`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 171. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:192`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 172. [INFO] Sensitive data access - consider audit logging for compliance

- **Location:** `api_views/users.py:195`
- **Rule ID:** rules.py-sensitive-access-no-log
- **Scanner:** N/A

**Description:** No description available

### 173. [INFO] session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754)

- **Location:** `api_views/users.py:196`
- **Rule ID:** rules.py-sqlalchemy-commit-no-except
- **Scanner:** N/A

**Description:** No description available

### 174. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:201`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 175. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:201`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 176. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:203`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 177. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:203`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 178. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:209`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 179. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:209`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 180. [INFO] User lookup pattern - ensure same error message for user not found and wrong password (CWE-204)

- **Location:** `api_views/users.py:211`
- **Rule ID:** rules.py-user-query-enumeration
- **Scanner:** N/A

**Description:** No description available

### 181. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:218`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 182. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:218`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 183. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:220`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 184. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:220`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 185. [INFO] Response without Content-Security-Policy header

- **Location:** `api_views/users.py:222`
- **Rule ID:** rules.py-response-no-csp
- **Scanner:** N/A

**Description:** No description available

### 186. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `api_views/users.py:222`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 187. [INFO] Debug mode may be enabled - ensure disabled in production

- **Location:** `app.py:17`
- **Rule ID:** rules.py-fastapi-debug-variable
- **Scanner:** N/A

**Description:** No description available

### 188. [INFO] SQLite database file - ensure not web-accessible and properly backed up (CWE-219)

- **Location:** `config.py:9`
- **Rule ID:** rules.py-sqlite-project-dir
- **Scanner:** N/A

**Description:** No description available

### 189. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `config.py:24`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 190. [INFO] Function accepts user_id parameter - ensure authorization check before accessing user resources (CWE-639)

- **Location:** `models/books_model.py:15`
- **Rule ID:** rules.py-idor-user-id-param
- **Scanner:** N/A

**Description:** No description available

### 191. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/books_model.py:21`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 192. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/books_model.py:24`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 193. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/books_model.py:28`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 194. [INFO] Password in constructor - consider adding password strength validation (CWE-521)

- **Location:** `models/user_model.py:21`
- **Rule ID:** rules.py-weak-password-policy
- **Scanner:** N/A

**Description:** No description available

### 195. [INFO] Sensitive data access - consider audit logging for compliance

- **Location:** `models/user_model.py:24`
- **Rule ID:** rules.py-sensitive-access-no-log
- **Scanner:** N/A

**Description:** No description available

### 196. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/user_model.py:28`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 197. [INFO] Function accepts user_id parameter - ensure authorization check before accessing user resources (CWE-639)

- **Location:** `models/user_model.py:30`
- **Rule ID:** rules.py-idor-user-id-param
- **Scanner:** N/A

**Description:** No description available

### 198. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/user_model.py:37`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 199. [INFO] JWT encoding - ensure secret key is not weak/hardcoded

- **Location:** `models/user_model.py:37`
- **Rule ID:** rules.py-jwt-encode-config-secret
- **Scanner:** N/A

**Description:** No description available

### 200. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/user_model.py:43`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 201. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/user_model.py:49`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 202. [INFO] FastAPI endpoint returning dict - consider using response_model for schema validation

- **Location:** `models/user_model.py:51`
- **Rule ID:** rules.py-fastapi-return-dict
- **Scanner:** N/A

**Description:** No description available

### 203. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/user_model.py:51`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 204. [INFO] FastAPI endpoint returning dict - consider using response_model for schema validation

- **Location:** `models/user_model.py:53`
- **Rule ID:** rules.py-fastapi-return-dict
- **Scanner:** N/A

**Description:** No description available

### 205. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/user_model.py:53`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 206. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/user_model.py:56`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 207. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/user_model.py:59`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 208. [INFO] Sensitive data access - consider audit logging for compliance

- **Location:** `models/user_model.py:59`
- **Rule ID:** rules.py-sensitive-access-no-log
- **Scanner:** N/A

**Description:** No description available

### 209. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/user_model.py:63`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 210. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/user_model.py:67`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 211. [INFO] CTF flag in response - this indicates an intentional vulnerability for testing

- **Location:** `models/user_model.py:71`
- **Rule ID:** rules.py-ctf-flag-response
- **Scanner:** N/A

**Description:** No description available

### 212. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/user_model.py:81`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 213. [INFO] session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754)

- **Location:** `models/user_model.py:89`
- **Rule ID:** rules.py-sqlalchemy-commit-no-except
- **Scanner:** N/A

**Description:** No description available

### 214. [INFO] session.commit() without exception handling - wrap in try/except for rollback on failure (CWE-754)

- **Location:** `models/user_model.py:94`
- **Rule ID:** rules.py-sqlalchemy-commit-no-except
- **Scanner:** N/A

**Description:** No description available

### 215. [INFO] Returning item directly - verify user has access to this item before returning (CWE-285)

- **Location:** `models/user_model.py:95`
- **Rule ID:** rules.py-fastapi-return-item-no-auth
- **Scanner:** N/A

**Description:** No description available

### 216. [INFO] OpenAPI spec - consider documenting rate limiting with x-ratelimit extension (OWASP API4).

- **Location:** `openapi_specs/openapi3.yml:1`
- **Rule ID:** rules.openapi-no-rate-limiting
- **Scanner:** N/A

**Description:** No description available

### 217. [INFO] OpenAPI paths without security requirement. Endpoints may be unauthenticated (OWASP API2).

- **Location:** `openapi_specs/openapi3.yml:15`
- **Rule ID:** rules.openapi-no-security-requirement
- **Scanner:** N/A

**Description:** No description available


---

## Next Steps

1. **Prioritize Critical/High findings** - These pose the greatest risk
2. **Use `scanner_master_prompt`** - Get actionable fix instructions for all issues
3. **Re-scan after fixes** - Verify vulnerabilities are resolved
4. **View online:** https://scanner.vibeship.co/scan/0dc0b815-0c11-4130-b8fb-e7a2ca4ae2ee

---

*Report generated by [Vibeship Scanner](https://vibeship.co)*

