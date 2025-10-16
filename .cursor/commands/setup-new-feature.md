# Backend Feature Setup

## Overview

Systematically set up a new feature from initial planning through to implementation structure.

## Before Coding

- [ ] Feature scope is clear and documented
- [ ] Acceptance criteria defined (what makes it "done")
- [ ] Breaking changes identified (if any)
- [ ] Dependencies reviewed (new packages needed?)

## Branch & Environment

- [ ] Feature branch created from dev
- [ ] Branch name follows convention (`feature/user-auth`)
- [ ] Local environment runs without errors
- [ ] Database migrations planned (if needed)

## Architecture Planning

- [ ] Database schema changes identified
- [ ] New tables/columns documented
- [ ] API endpoints defined (method, path, request/response)
- [ ] Data models/structs designed
- [ ] Error handling strategy considered

## Implementation Structure

- [ ] File structure planned (controllers, services, usecases,repositories)
- [ ] Interfaces defined for testability
- [ ] Third-party integrations identified
- [ ] Configuration variables added to `.env.example`

## Testing Strategy

- [ ] Unit tests approach planned
- [ ] Integration tests needed identified
- [ ] Test data requirements known
- [ ] Edge cases listed

## Documentation

- [ ] API endpoints added to docs (Swagger/OpenAPI if used)
- [ ] README updated if new setup steps needed
- [ ] Environment variables documented
