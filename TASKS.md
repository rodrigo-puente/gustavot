# Multi-Tenant SaaS Implementation Plan

## How to Use This Plan
Each task is designed to be:
- **Small and testable**: Complete in 1-2 hours max
- **Browser-verifiable**: You can test it manually in the browser
- **Test-covered**: Includes corresponding automated tests
- **Independent**: Can be completed and verified before moving on

Mark tasks with [x] as you complete them.

## Important: Hotwire + Stimulus First

**Use Hotwire (Turbo) and Stimulus for interactive features** instead of writing custom JavaScript:

### When to Use Hotwire/Stimulus:
- ✅ **Form submissions**: Use Turbo Frames for inline updates
- ✅ **Live updates**: Use Turbo Streams for real-time changes
- ✅ **Modals/Dropdowns**: Use Stimulus controllers for behavior
- ✅ **Organization switching**: Turbo Frame replaces content without full reload
- ✅ **Invitation acceptance**: Turbo Stream updates UI after action
- ✅ **Flash messages**: Auto-dismiss with Stimulus
- ✅ **Form validation**: Client-side validation with Stimulus
- ✅ **Loading states**: Stimulus controller adds/removes classes

### Good Use Cases in This Project:
- Organization switcher dropdown (Stimulus)
- Accepting/rejecting invitations (Turbo Streams)
- 2FA code input (Stimulus for auto-focus, auto-submit)
- Member role updates (Turbo Frame for inline editing)
- Resend SMS code (Turbo Stream for countdown timer)
- Transfer ownership confirmation modal (Stimulus)

### Rails 8 Defaults:
Rails 8 includes Hotwire by default. No extra setup needed!

**Principle**: Keep JavaScript minimal. Use server-rendered HTML with Turbo/Stimulus for interactivity.

---

## PHASE 1: Foundation & Basic Authentication

### 1.1 Project Setup
- [x] **Task**: Initialize Rails 8 app with PostgreSQL
  - Run: `rails new gustavot --database=postgresql --css=tailwind`
  - Create database
  - **Browser Test**: Visit `localhost:3000` � see Rails welcome page
  - **Tests**: None needed yet

### 1.2 Install DaisyUI
- [x] **Task**: Add DaisyUI to Tailwind
  - Install via npm/yarn
  - Configure `tailwind.config.js`
  - Create test page with DaisyUI button
  - **Browser Test**: Visit test page � see styled DaisyUI button
  - **Tests**: None needed

### 1.3 Install and Configure Devise
- [x] **Task**: Basic Devise setup
  - Install Devise gem
  - Run `rails generate devise:install`
  - Generate User model: `rails generate devise User`
  - Add basic fields: `first_name`, `last_name` to migration
  - Run migrations
  - **Browser Test**: Visit `/users/sign_up` � see registration form
  - **Tests**: User model test (validates presence)

### 1.4 Customize Registration Form
- [x] **Task**: Add all user fields to registration
  - Migration: Add `date_of_birth`, `phone_number`, `country_code` to users
  - Update strong parameters in `ApplicationController`
  - Generate Devise views: `rails generate devise:views`
  - Style registration form with DaisyUI
  - Add fields: first_name, last_name, date_of_birth, phone_number
  - **Browser Test**: Fill registration form � user created � redirected
  - **Tests**:
    - User validation tests
    - Registration controller test

### 1.5 Basic Dashboard
- [ ] **Task**: Create authenticated home page
  - Generate DashboardController with index action
  - Add `authenticated_root` route
  - Create simple dashboard view with DaisyUI card
  - Show "Welcome [First Name]!" message
  - Add sign out button
  - **Browser Test**: Register � redirected to dashboard � see welcome message
  - **Tests**: Dashboard controller test (requires authentication)

---

## PHASE 2: Organizations & Memberships

### 2.1 Organization Model
- [ ] **Task**: Create Organization model
  - Generate model: `rails generate model Organization name:string subdomain:string`
  - Add validations and uniqueness constraints
  - Create helper method for subdomain generation
  - **Browser Test**: Rails console � create organization � check subdomain
  - **Tests**:
    - Organization model validations
    - Subdomain uniqueness
    - Subdomain generation

### 2.2 Organization Membership Model
- [ ] **Task**: Create join table
  - Generate model: `rails generate model OrganizationMembership user:references organization:references role:string`
  - Add unique index on [user_id, organization_id]
  - Add unique owner constraint
  - Add associations to User and Organization models
  - **Browser Test**: Rails console � create membership � check associations
  - **Tests**:
    - Membership validations
    - One owner per org constraint
    - Association tests

### 2.3 Auto-Create Organization on Registration
- [ ] **Task**: Hook into Devise registration
  - Override `RegistrationsController`
  - After user creation � create organization � create membership (owner role)
  - **Browser Test**: Register new user � check DB � user has 1 org as owner
  - **Tests**:
    - Registration creates organization
    - Membership created with OWNER role
    - Integration test

### 2.4 Display Current Organization
- [ ] **Task**: Show organization in dashboard
  - Add `current_organization` helper method (uses first org for now)
  - Update dashboard to display organization name
  - **Browser Test**: Login � see organization name on dashboard
  - **Tests**: Helper method test

---

## PHASE 3: SMS-Based 2FA

### 3.1 Add 2FA Fields to User
- [ ] **Task**: Migration for 2FA fields
  - Add columns: `two_factor_code`, `two_factor_code_sent_at`, `two_factor_verified`
  - Run migration
  - **Browser Test**: Rails console � check user has new columns
  - **Tests**: None needed

### 3.2 Create SMS Service (Stubbed)
- [ ] **Task**: Build SMS service without Twilio
  - Create `app/services/sms_service.rb`
  - Implement `send_code(phone_number, code)` that logs to console
  - **Browser Test**: Rails console � SmsService.send_code(...) � see log
  - **Tests**: Service test (mocked)

### 3.3 Generate and Store 2FA Code
- [ ] **Task**: Code generation logic
  - Create `User#generate_two_factor_code!` method
  - Generates 6-digit code
  - Hashes and stores in DB
  - Stores timestamp
  - **Browser Test**: Rails console � user.generate_two_factor_code! � check DB
  - **Tests**:
    - Code generation
    - Code hashing
    - Timestamp storage

### 3.4 Override Devise Login Flow
- [ ] **Task**: Intercept after password validation
  - Override `SessionsController#create`
  - After valid password � generate code � send SMS � redirect to 2FA page
  - Don't sign in user yet
  - **Browser Test**: Login with email/password � redirected to 2FA page (no SMS yet)
  - **Tests**: Sessions controller test

### 3.5 2FA Verification Page
- [ ] **Task**: Build verification form
  - Create view for entering 6-digit code
  - Style with DaisyUI
  - Add "Resend code" link
  - **Browser Test**: Login � see 2FA form with input field
  - **Tests**: View test (form present)

### 3.6 Verify 2FA Code
- [ ] **Task**: Code verification logic
  - Create `verify_two_factor` action in SessionsController
  - Check code matches hash
  - Check not expired (60s)
  - Sign in user if valid
  - **Browser Test**: Login � enter correct code � signed in � dashboard
  - **Tests**:
    - Valid code signs in user
    - Invalid code shows error
    - Expired code shows error

### 3.7 Integrate Real Twilio (Production Only)
- [ ] **Task**: Add Twilio gem and configure
  - Add `twilio-ruby` gem
  - Configure ENV variables
  - Update SmsService to use Twilio only if `ENV['TWILIO_ACCOUNT_SID']` present
  - **Browser Test**: Set ENV vars � login � receive real SMS
  - **Tests**: Service test with VCR or stubbed

---

## PHASE 4: Session Management

### 4.1 Session Expiry
- [ ] **Task**: Track session expiry time
  - Store `session_expires_at` in session on login
  - Set to 72 hours from now
  - **Browser Test**: Login � check session cookie � see expiry
  - **Tests**: Session controller test

### 4.2 Session Validation Middleware
- [ ] **Task**: Check expiry on each request
  - Create `before_action :check_session_expiry` in ApplicationController
  - If expired � sign out � redirect to login
  - **Browser Test**: Manually expire session � refresh � redirected to login
  - **Tests**: Application controller test

---

## PHASE 5: Multi-Organization Support

### 5.1 Organization Selection Page
- [ ] **Task**: List user's organizations
  - Create `OrganizationsController#index`
  - Display all user's organizations with their roles
  - Style with DaisyUI cards
  - **Browser Test**: Visit `/organizations` � see list of orgs
  - **Tests**: Controller test

### 5.2 Set Current Organization in Session
- [ ] **Task**: Select organization
  - Add `OrganizationsController#select` action
  - Store `current_organization_id` in session
  - Redirect to dashboard
  - **Browser Test**: Select org � dashboard shows selected org
  - **Tests**: Controller test

### 5.3 Organization Switcher Dropdown
- [ ] **Task**: Add dropdown to navbar
  - Create navbar partial with DaisyUI dropdown
  - List all user's organizations
  - Highlight current organization
  - Click to switch
  - **Browser Test**: See dropdown � click org � page reloads � switched
  - **Tests**: Integration test

### 5.4 Force Organization Selection After Login
- [ ] **Task**: Redirect to selection if no current org
  - Add `before_action :ensure_current_organization` to DashboardController
  - Skip if on organization pages
  - **Browser Test**: Login � auto-redirected to org selection
  - **Tests**: Controller test

---

## PHASE 6: Pundit Authorization Setup

### 6.1 Install Pundit
- [ ] **Task**: Basic Pundit setup
  - Add `pundit` gem
  - Run `rails generate pundit:install`
  - Include Pundit in ApplicationController
  - Add `rescue_from Pundit::NotAuthorizedError`
  - **Browser Test**: None yet
  - **Tests**: None yet

### 6.2 Current Membership Helper
- [ ] **Task**: Get user's membership in current org
  - Create `current_membership` helper in ApplicationController
  - Returns OrganizationMembership for current_user and current_organization
  - **Browser Test**: Rails console � current_membership � check role
  - **Tests**: Helper test

### 6.3 Organization Policy
- [ ] **Task**: Create basic policy
  - Generate: `rails generate pundit:policy Organization`
  - Implement: `show?`, `update?`, `destroy?`
  - Use current_membership for checks
  - **Browser Test**: None yet
  - **Tests**:
    - Policy tests for all roles
    - Owner can update
    - Admin can update
    - Support Agent cannot update

### 6.4 Apply Policy to Organization Controller
- [ ] **Task**: Protect organization actions
  - Add `authorize @organization` to OrganizationsController
  - Test unauthorized access
  - **Browser Test**: Login as support agent � try to edit org � see error
  - **Tests**: Controller test (authorization)

---

## PHASE 7: Member Management

### 7.1 Members List Page
- [ ] **Task**: Display organization members
  - Create `MembershipsController#index`
  - Display table with: name, email, role, joined date
  - Style with DaisyUI table
  - **Browser Test**: Visit `/organizations/:id/members` � see members list
  - **Tests**: Controller test

### 7.2 Membership Policy
- [ ] **Task**: Create policy for viewing members
  - Generate: `rails generate pundit:policy OrganizationMembership`
  - Implement: `index?`, `update?`, `destroy?`
  - All roles can view, only Owner/Admin can modify
  - **Browser Test**: Login as support agent � can view, cannot edit
  - **Tests**: Policy tests

### 7.3 Change Member Role
- [ ] **Task**: Update member role
  - Create `MembershipsController#update`
  - Only Owner/Admin can change roles
  - Cannot change own role
  - **Browser Test**: Change member role � see updated role
  - **Tests**:
    - Controller test
    - Cannot change own role
    - Authorization test

### 7.4 Remove Member
- [ ] **Task**: Delete membership
  - Create `MembershipsController#destroy`
  - Only Owner/Admin can remove
  - Cannot remove self
  - Cannot remove owner
  - **Browser Test**: Remove member � member no longer listed
  - **Tests**:
    - Controller test
    - Validation tests

---

## PHASE 8: Invitation System

### 8.1 Invitation Model
- [ ] **Task**: Create invitation model
  - Generate: `rails generate model Invitation organization:references invited_by:references email:string role:string token:string status:string expires_at:datetime`
  - Add validations and indexes
  - Add associations
  - **Browser Test**: Rails console � create invitation
  - **Tests**: Model validations

### 8.2 Send Invitation Form
- [ ] **Task**: Create invitation form
  - Create `InvitationsController#new` and `#create`
  - Form: email input + role dropdown (Admin/Support Agent only)
  - Generate token and set expiry (7 days)
  - **Browser Test**: Fill form � invitation created in DB
  - **Tests**:
    - Controller test
    - Token generation
    - Expiry set correctly

### 8.3 Invitation Policy
- [ ] **Task**: Protect invitation creation
  - Generate: `rails generate pundit:policy Invitation`
  - Only Owner/Admin can create
  - **Browser Test**: Login as support agent � cannot access invite form
  - **Tests**: Policy tests

### 8.4 Invitation Email (Letter Opener)
- [ ] **Task**: Send email with invitation link
  - Install `letter_opener` gem
  - Create `InvitationMailer`
  - Email includes: org name, role, accept link
  - **Browser Test**: Send invitation � letter_opener shows email
  - **Tests**: Mailer test

### 8.5 View Invitation Page
- [ ] **Task**: Public invitation acceptance page
  - Create `InvitationsController#show` (no auth required)
  - Display: org name, role, invited by
  - Buttons: Accept / Reject
  - **Browser Test**: Visit invitation link � see details
  - **Tests**: Controller test

### 8.6 Accept Invitation (Existing User)
- [ ] **Task**: Accept invitation flow
  - If not logged in � redirect to login with return path
  - After login � create membership
  - Mark invitation as accepted
  - **Browser Test**: Click accept � login � membership created
  - **Tests**:
    - Integration test
    - Membership created
    - Invitation marked accepted

### 8.7 Reject Invitation
- [ ] **Task**: Reject invitation flow
  - Update invitation status to rejected
  - Show "Invitation declined" message
  - **Browser Test**: Click reject � see confirmation
  - **Tests**: Controller test

### 8.8 Accept Invitation (New User)
- [ ] **Task**: Registration from invitation
  - Store invitation token in session
  - After registration � auto-accept invitation
  - **Browser Test**: New user clicks invite � registers � auto-joined
  - **Tests**: Integration test

### 8.9 Invitation Expiry Job
- [ ] **Task**: Background job to expire invitations
  - Install Sidekiq
  - Create `ExpireInvitationsJob`
  - Marks invitations older than 7 days as expired
  - Schedule daily
  - **Browser Test**: Rails console � run job � check expired invitations
  - **Tests**: Job test

### 8.10 Handle Expired Invitations
- [ ] **Task**: Show expired message
  - Check if invitation expired when viewing
  - Show error message with "Contact admin" prompt
  - **Browser Test**: Visit expired invitation � see error
  - **Tests**: Controller test

---

## PHASE 9: Owner Transfer

### 9.1 Transfer Ownership UI
- [ ] **Task**: Add transfer button to members page
  - Show "Transfer Ownership" button next to admins
  - Only visible to owner
  - **Browser Test**: Login as owner � see transfer button next to admins
  - **Tests**: View test

### 9.2 Transfer Ownership Action
- [ ] **Task**: Implement ownership transfer
  - Create `MembershipsController#transfer_ownership`
  - Current owner � admin
  - Target admin � owner
  - Confirmation modal with DaisyUI
  - **Browser Test**: Transfer ownership � roles swapped
  - **Tests**:
    - Controller test
    - Only owner can transfer
    - Can only transfer to admin

---

## PHASE 10: Profile Management

### 10.1 Edit Profile Page
- [ ] **Task**: User can edit basic info
  - Create `ProfilesController`
  - Edit form: first_name, last_name, date_of_birth
  - Style with DaisyUI
  - **Browser Test**: Edit profile � changes saved
  - **Tests**: Controller test

### 10.2 Change Email with Verification
- [ ] **Task**: Email change workflow
  - Update email � send verification email
  - Click link � email updated
  - **Browser Test**: Change email � verify � email updated
  - **Tests**:
    - Controller test
    - Mailer test
    - Integration test

### 10.3 Change Phone with SMS Verification
- [ ] **Task**: Phone change workflow
  - Update phone � send SMS code
  - Enter code � phone updated
  - **Browser Test**: Change phone � enter code � updated
  - **Tests**:
    - Controller test
    - Verification test

---

## PHASE 11: Security & Polish

### 11.1 Rate Limiting
- [ ] **Task**: Install and configure rack-attack
  - Add `rack-attack` gem
  - Limit login attempts: 5 per 10 minutes
  - Limit SMS sends: 3 per 10 minutes
  - Limit invitations: 10 per hour
  - **Browser Test**: Trigger rate limit � see error
  - **Tests**: Request test

### 11.2 Error Handling
- [ ] **Task**: Custom error pages
  - 404, 500 pages with DaisyUI
  - Unauthorized page
  - **Browser Test**: Visit bad route � see styled 404
  - **Tests**: None needed

### 11.3 Comprehensive Test Suite
- [ ] **Task**: Fill testing gaps
  - Model tests for all models
  - Policy tests for all policies
  - Controller tests for all actions
  - Integration tests for critical flows
  - Aim for 90%+ coverage
  - **Browser Test**: Run `rails test` � all green
  - **Tests**: All tests pass

### 11.4 UI Polish
- [ ] **Task**: Improve user experience
  - Loading states for forms
  - Success/error flash messages
  - Mobile responsive checks
  - Accessibility improvements
  - **Browser Test**: Navigate app � smooth UX
  - **Tests**: None needed

---

## PHASE 12: Deployment Prep

### 12.1 Environment Configuration
- [ ] **Task**: Set up ENV vars
  - Document all required ENV variables
  - Create `.env.example`
  - Configure production settings
  - **Browser Test**: None
  - **Tests**: None

### 12.2 Database Seeds
- [ ] **Task**: Create seed data
  - Sample users, organizations, memberships
  - Use FactoryBot/Faker
  - **Browser Test**: Run `rails db:seed` � data created
  - **Tests**: None

### 12.3 Production Readiness
- [ ] **Task**: Final checks
  - Asset precompilation works
  - Database migrations run
  - Twilio production credentials
  - Redis/Sidekiq configured
  - **Browser Test**: Test on staging
  - **Tests**: Smoke tests

---

## Notes

### Testing Strategy
- **Unit Tests**: All models, services, policies, helpers
- **Controller Tests**: All actions with authorization checks
- **Integration Tests**: Complete user flows (registration, login, invitations)
- **Use shoulda-matchers**: For cleaner model tests
- **Use shoulda-context**: For organizing test scenarios

### Browser Testing Checklist Per Task
1. Happy path works
2. Error cases handled gracefully
3. Authorization respected
4. UI looks good (DaisyUI styled)
5. Mobile responsive

### Development Workflow
1. Read task description
2. Write failing test(s)
3. Implement feature
4. Verify tests pass
5. Test manually in browser
6. Mark task complete
7. Commit changes

---

## Quick Start Checklist

Before starting:
- [ ] Ruby 3.x installed
- [ ] Rails 8 installed
- [ ] PostgreSQL installed and running
- [ ] Node.js and Yarn installed
- [ ] Redis installed (for Sidekiq later)
- [ ] Create `gustavot` database

Ready to start? Begin with **Task 1.1**!
