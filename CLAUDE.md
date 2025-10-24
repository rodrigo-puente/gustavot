# Multi-Tenant SaaS Application

## Overview
Multi-tenant SaaS with role-based access control, 2FA authentication, and organization management.

## Tech Stack
- **Backend**: Rails 8, PostgreSQL, Devise, Pundit
- **Frontend**: Tailwind CSS, DaisyUI, ERB/Hotwire
- **Services**: Twilio (SMS 2FA), Sidekiq + Redis
- **Testing**: Minitest, shoulda-matchers, shoulda-context

## Core Features
- User registration with auto-organization creation
- Multi-organization membership
- Email invitations (7-day expiry)
- SMS-based 2FA (required for all logins)
- Role-based access (Owner, Admin, Support Agent)
- Organization switching
- 72-hour session expiry

## Database Schema

### Users
- Email, password (Devise)
- first_name, last_name, date_of_birth
- phone_number (unique), country_code
- 2FA: two_factor_code, two_factor_code_sent_at, two_factor_verified

### Organizations
- name, subdomain (unique)

### OrganizationMemberships
- user_id, organization_id, role (OWNER/ADMIN/SUPPORT_AGENT)
- Constraints: one membership per user/org, one owner per org

### Invitations
- organization_id, invited_by_id, email, role, token (unique)
- status (pending/accepted/rejected/expired), expires_at

## Key Business Rules
- One owner per organization (transferable to admins only)
- Email and phone must be unique system-wide
- Invitations expire after 7 days
- Sessions expire after 72 hours
- 2FA code valid for 60 seconds

## Authorization (Pundit)

| Action | OWNER | ADMIN | SUPPORT_AGENT |
|--------|-------|-------|---------------|
| View org | ✓ | ✓ | ✓ |
| Edit org settings | ✓ | ✓ | ✗ |
| View/Invite/Remove members | ✓ | ✓ | ✗ |
| Transfer ownership | ✓ | ✗ | ✗ |
| Delete organization | ✓ | ✗ | ✗ |

## User Flows

### Registration
1. User fills form (email, password, name, DOB, phone)
2. System creates user + organization + owner membership
3. SMS code sent → user verifies → redirect to dashboard

### Login
1. Email + password → SMS code sent
2. User enters code (60s validity)
3. Session created (72h) → org selection/dashboard

### Invitations
1. Owner/Admin sends invite (email + role)
2. Email sent with unique token link
3. Recipient accepts/rejects → membership created or invitation marked rejected

### Organization Switching
- Sidebar dropdown shows all user's organizations
- Click to switch → updates session → page reloads

## Security
- **2FA**: SHA256 hashed codes, 60s validity, rate limited (3 SMS/10min)
- **Sessions**: 72h expiry, encrypted cookies
- **Invitations**: SecureRandom tokens, 7-day expiry
- **Passwords**: BCrypt (8+ chars)
- **Rate Limiting**: rack-attack for login/SMS/invitations

## Environment Variables
```bash
DATABASE_URL=postgresql://...
REDIS_URL=redis://localhost:6379/0
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...
TWILIO_PHONE_NUMBER=+1234567890
DEVISE_SECRET_KEY=...
SECRET_KEY_BASE=...
```

## Development Setup
```ruby
# Key Gems
gem 'devise', 'pundit', 'twilio-ruby', 'sidekiq', 'rack-attack'
gem 'tailwindcss-rails'
gem 'letter_opener' # dev emails
gem 'factory_bot_rails', 'faker', 'shoulda-matchers' # testing
```

## Implementation Phases
1. **Foundation**: Devise, 2FA, models, Pundit setup
2. **Multi-tenancy**: Org switching, subdomain management, member management
3. **Invitations**: Full invitation workflow
4. **Advanced**: Owner transfer, profile editing
5. **Polish**: Testing, security audit, rate limiting
6. **Deploy**: Production setup, monitoring
