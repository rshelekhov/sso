# Code Review Checklist

## Overview

Comprehensive checklist for conducting thorough code reviews to ensure quality, security, and maintainability.

## Functionality

- [ ] Code works as intended
- [ ] Edge cases are handled
- [ ] All errors are checked (no ignored errors with `_`)
- [ ] Errors are wrapped with context using `fmt.Errorf` with `%w`

## Go-Specific

- [ ] No goroutine leaks (channels closed, contexts with timeouts)
- [ ] `defer` is used correctly (especially in loops)
- [ ] `context.Context` is used for cancellation
- [ ] No race conditions on shared state
- [ ] Efficient memory usage (no unnecessary allocations in loops)
- [ ] Correct pointer vs value usage

## Code Quality

- [ ] Code is readable and well-structured
- [ ] Functions are focused and not too long (under 100 lines)
- [ ] Variable and function names are clear and descriptive
- [ ] No unnecessary code duplication
- [ ] Code follows `gofmt` and `goimports` formatting

## Database

- [ ] SQL injection is prevented (using prepared statements or ORM)
- [ ] Database connections don't leak
- [ ] Transactions are used correctly
- [ ] No N+1 query problems

## Security

- [ ] Input validation is present
- [ ] Sensitive data is not logged
- [ ] No hardcoded secrets or credentials
- [ ] Authentication and authorization are correct

## API

- [ ] Correct HTTP status codes are used
- [ ] Request data is validated
- [ ] JSON serialization/deserialization is correct
- [ ] Error responses are informative but don't leak internals

## Testing

- [ ] Unit tests cover new functionality
- [ ] Tests include edge cases
- [ ] Table-driven tests are used where appropriate

## Logging

- [ ] Structured logging is used
- [ ] Appropriate log levels are used
- [ ] Sensitive data is not logged
