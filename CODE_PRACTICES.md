# Code Practices & Implementation Guide

This document contains code examples, patterns, and best practices for implementing the multi-tenant SaaS application described in [PROJECT_SPECIFICATION.md](PROJECT_SPECIFICATION.md).

## Table of Contents
1. [Devise Configuration](#devise-configuration)
2. [Two-Factor Authentication](#two-factor-authentication)
3. [Pundit Authorization](#pundit-authorization)
4. [Models & Associations](#models--associations)
5. [Controllers](#controllers)
6. [Views with DaisyUI](#views-with-daisyui)
7. [Background Jobs](#background-jobs)
8. [Testing](#testing)

---

## Devise Configuration

### Installation & Setup

```bash
bundle add devise
rails generate devise:install
rails generate devise User
```

### Custom Devise Configuration

```ruby
# config/initializers/devise.rb
Devise.setup do |config|
  config.mailer_sender = 'noreply@yourdomain.com'

  # Session timeout: 72 hours
  config.timeout_in = 72.hours

  # Password requirements
  config.password_length = 8..128
  config.email_regexp = /\A[^@\s]+@[^@\s]+\z/

  # Lockable settings (optional - for brute force protection)
  config.lock_strategy = :failed_attempts
  config.unlock_strategy = :time
  config.maximum_attempts = 5
  config.unlock_in = 1.hour
end
```

### User Migration

```ruby
# db/migrate/[timestamp]_devise_create_users.rb
class DeviseCreateUsers < ActiveRecord::Migration[8.0]
  def change
    create_table :users do |t|
      ## Devise
      t.string :email, null: false, default: ""
      t.string :encrypted_password, null: false, default: ""
      t.string :reset_password_token
      t.datetime :reset_password_sent_at
      t.datetime :remember_created_at

      ## Lockable (optional)
      t.integer  :failed_attempts, default: 0, null: false
      t.string   :unlock_token
      t.datetime :locked_at

      ## Profile
      t.string :first_name, null: false
      t.string :last_name, null: false
      t.date :date_of_birth
      t.string :phone_number, null: false
      t.string :country_code, null: false, default: '+1'

      ## 2FA
      t.boolean :two_factor_enabled, default: true
      t.string :two_factor_code
      t.datetime :two_factor_code_sent_at
      t.boolean :two_factor_verified, default: false

      ## Trackable
      t.datetime :current_sign_in_at
      t.datetime :last_sign_in_at
      t.string :current_sign_in_ip
      t.string :last_sign_in_ip

      t.timestamps null: false
    end

    add_index :users, :email, unique: true
    add_index :users, :reset_password_token, unique: true
    add_index :users, :unlock_token, unique: true
    add_index :users, :phone_number, unique: true
  end
end
```

---

## Two-Factor Authentication

### User Model Concern

```ruby
# app/models/concerns/two_factor_authenticatable.rb
module TwoFactorAuthenticatable
  extend ActiveSupport::Concern

  # Generate a 6-digit code and store hashed version
  def generate_two_factor_code
    code = format('%06d', rand(0..999999))
    self.update(
      two_factor_code: Digest::SHA256.hexdigest(code),
      two_factor_code_sent_at: Time.current,
      two_factor_verified: false
    )
    code # Return plain code for SMS
  end

  # Verify the code entered by user
  def verify_two_factor_code(input_code)
    return false if two_factor_code_expired?
    return false if two_factor_code.blank?

    Digest::SHA256.hexdigest(input_code) == two_factor_code
  end

  # Check if code is expired (60 seconds)
  def two_factor_code_expired?
    return true if two_factor_code_sent_at.blank?
    two_factor_code_sent_at < 60.seconds.ago
  end

  # Mark 2FA as verified
  def mark_two_factor_verified!
    update(two_factor_verified: true, two_factor_code: nil)
  end

  # Check if user needs 2FA verification
  def needs_two_factor_verification?
    two_factor_enabled? && !two_factor_verified?
  end
end
```

### SMS Service

```ruby
# app/services/sms_service.rb
class SmsService
  class << self
    def send_two_factor_code(user, code)
      client = Twilio::REST::Client.new(
        ENV['TWILIO_ACCOUNT_SID'],
        ENV['TWILIO_AUTH_TOKEN']
      )

      client.messages.create(
        from: ENV['TWILIO_PHONE_NUMBER'],
        to: "#{user.country_code}#{user.phone_number}",
        body: "Your verification code is: #{code}. Valid for 60 seconds."
      )
    rescue Twilio::REST::RestError => e
      Rails.logger.error "Failed to send SMS: #{e.message}"
      raise
    end

    def send_verification_code(phone_number, country_code, code)
      client = Twilio::REST::Client.new(
        ENV['TWILIO_ACCOUNT_SID'],
        ENV['TWILIO_AUTH_TOKEN']
      )

      client.messages.create(
        from: ENV['TWILIO_PHONE_NUMBER'],
        to: "#{country_code}#{phone_number}",
        body: "Your verification code is: #{code}. Valid for 60 seconds."
      )
    rescue Twilio::REST::RestError => e
      Rails.logger.error "Failed to send SMS: #{e.message}"
      raise
    end
  end
end
```

### Two-Factor Controller

```ruby
# app/controllers/two_factor_authentication_controller.rb
class TwoFactorAuthenticationController < ApplicationController
  skip_before_action :authenticate_user!, only: [:show, :verify]
  before_action :require_login_session

  def show
    # Show 2FA verification form
    @user = User.find(session[:pending_user_id])
  end

  def verify
    @user = User.find(session[:pending_user_id])

    if @user.verify_two_factor_code(params[:code])
      @user.mark_two_factor_verified!
      sign_in(@user)
      session.delete(:pending_user_id)

      redirect_to after_sign_in_path_for(@user), notice: 'Successfully signed in'
    else
      flash.now[:alert] = 'Invalid or expired code'
      render :show
    end
  end

  def resend
    @user = User.find(session[:pending_user_id])
    code = @user.generate_two_factor_code

    SmsService.send_two_factor_code(@user, code)

    redirect_to two_factor_authentication_path, notice: 'New code sent'
  end

  private

  def require_login_session
    redirect_to new_user_session_path unless session[:pending_user_id]
  end
end
```

### Custom Sessions Controller

```ruby
# app/controllers/users/sessions_controller.rb
class Users::SessionsController < Devise::SessionsController
  def create
    self.resource = warden.authenticate!(auth_options)

    if resource.two_factor_enabled?
      # Generate and send 2FA code
      code = resource.generate_two_factor_code
      SmsService.send_two_factor_code(resource, code)

      # Store user ID in session for 2FA verification
      session[:pending_user_id] = resource.id

      # Redirect to 2FA verification page
      redirect_to two_factor_authentication_path
    else
      # Normal sign in flow (if 2FA disabled)
      set_flash_message!(:notice, :signed_in)
      sign_in(resource_name, resource)
      respond_with resource, location: after_sign_in_path_for(resource)
    end
  end

  protected

  def after_sign_in_path_for(resource)
    # Redirect to organization selection or dashboard
    organizations_path
  end
end
```

---

## Pundit Authorization

### Installation & Setup

```bash
bundle add pundit
rails generate pundit:install
```

### Application Controller Setup

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  include Pundit::Authorization

  before_action :authenticate_user!
  before_action :set_current_organization

  rescue_from Pundit::NotAuthorizedError, with: :user_not_authorized

  private

  def set_current_organization
    if session[:current_organization_id]
      @current_organization = current_user.organizations.find_by(id: session[:current_organization_id])
      session[:current_organization_id] = nil unless @current_organization
    end

    @current_organization ||= current_user.organizations.first
    session[:current_organization_id] = @current_organization&.id
  end

  # Pundit uses this to pass context to policies
  def pundit_user
    CurrentContext.new(current_user, @current_organization)
  end

  def user_not_authorized
    flash[:alert] = "You are not authorized to perform this action."
    redirect_to(request.referer || root_path)
  end
end
```

### Current Context Object

```ruby
# app/models/current_context.rb
class CurrentContext
  attr_reader :user, :organization

  def initialize(user, organization)
    @user = user
    @organization = organization
  end

  def membership
    @membership ||= OrganizationMembership.find_by(
      user: user,
      organization: organization
    )
  end

  def role
    membership&.role
  end

  def owner?
    role == 'OWNER'
  end

  def admin?
    role == 'ADMIN'
  end

  def support_agent?
    role == 'SUPPORT_AGENT'
  end

  def can_manage?
    owner? || admin?
  end
end
```

### Application Policy (Base)

```ruby
# app/policies/application_policy.rb
class ApplicationPolicy
  attr_reader :context, :record

  def initialize(context, record)
    @context = context
    @record = record
  end

  def user
    context.user
  end

  def organization
    context.organization
  end

  def membership
    context.membership
  end

  def index?
    false
  end

  def show?
    false
  end

  def create?
    false
  end

  def new?
    create?
  end

  def update?
    false
  end

  def edit?
    update?
  end

  def destroy?
    false
  end

  class Scope
    def initialize(context, scope)
      @context = context
      @scope = scope
    end

    def resolve
      raise NotImplementedError, "You must define #resolve in #{self.class}"
    end

    private

    attr_reader :context, :scope

    def user
      context.user
    end

    def organization
      context.organization
    end
  end
end
```

### Organization Policy

```ruby
# app/policies/organization_policy.rb
class OrganizationPolicy < ApplicationPolicy
  def show?
    membership.present?
  end

  def update?
    context.can_manage?
  end

  def update_subdomain?
    context.can_manage?
  end

  def destroy?
    context.owner?
  end

  def transfer_ownership?
    context.owner?
  end

  def switch?
    user.organizations.include?(record)
  end

  class Scope < Scope
    def resolve
      user.organizations
    end
  end
end
```

### Organization Membership Policy

```ruby
# app/policies/organization_membership_policy.rb
class OrganizationMembershipPolicy < ApplicationPolicy
  def index?
    membership.present?
  end

  def show?
    membership.present? && record.organization == organization
  end

  def update?
    context.can_manage? && record.user != user && record.role != 'OWNER'
  end

  def destroy?
    context.can_manage? && record.user != user && record.role != 'OWNER'
  end

  class Scope < Scope
    def resolve
      scope.where(organization: organization)
    end
  end
end
```

### Invitation Policy

```ruby
# app/policies/invitation_policy.rb
class InvitationPolicy < ApplicationPolicy
  def index?
    context.can_manage?
  end

  def show?
    context.can_manage? || record.email == user.email
  end

  def create?
    context.can_manage?
  end

  def accept?
    record.email == user.email && record.pending? && !record.expired?
  end

  def reject?
    record.email == user.email && record.pending? && !record.expired?
  end

  def destroy?
    context.can_manage? && record.pending?
  end

  class Scope < Scope
    def resolve
      if context.can_manage?
        scope.where(organization: organization)
      else
        scope.where(email: user.email)
      end
    end
  end
end
```

---

## Models & Associations

### User Model

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include TwoFactorAuthenticatable

  # Devise modules
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :lockable, :trackable

  # Associations
  has_many :organization_memberships, dependent: :destroy
  has_many :organizations, through: :organization_memberships
  has_many :sent_invitations, class_name: 'Invitation',
           foreign_key: 'invited_by_id', dependent: :nullify

  # Validations
  validates :first_name, :last_name, presence: true
  validates :phone_number, presence: true, uniqueness: true
  validates :country_code, presence: true

  # Callbacks
  after_create :create_default_organization

  def full_name
    "#{first_name} #{last_name}"
  end

  def membership_in(organization)
    organization_memberships.find_by(organization: organization)
  end

  def role_in(organization)
    membership_in(organization)&.role
  end

  def owner?(organization)
    role_in(organization) == 'OWNER'
  end

  def admin?(organization)
    role_in(organization) == 'ADMIN'
  end

  def support_agent?(organization)
    role_in(organization) == 'SUPPORT_AGENT'
  end

  def can_manage?(organization)
    owner?(organization) || admin?(organization)
  end

  private

  def create_default_organization
    org = Organization.create!(
      name: "#{full_name}'s Organization",
      subdomain: generate_subdomain
    )

    organization_memberships.create!(
      organization: org,
      role: 'OWNER'
    )
  end

  def generate_subdomain
    loop do
      subdomain = "#{SecureRandom.hex(4)}-#{Time.current.to_i.to_s(36)}"
      break subdomain unless Organization.exists?(subdomain: subdomain)
    end
  end
end
```

### Organization Model

```ruby
# app/models/organization.rb
class Organization < ApplicationRecord
  # Associations
  has_many :organization_memberships, dependent: :destroy
  has_many :users, through: :organization_memberships
  has_many :invitations, dependent: :destroy

  has_one :owner_membership, -> { where(role: 'OWNER') },
          class_name: 'OrganizationMembership'
  has_one :owner, through: :owner_membership, source: :user

  # Validations
  validates :name, presence: true
  validates :subdomain, presence: true, uniqueness: true,
            format: { with: /\A[a-z0-9\-]+\z/,
                      message: "only allows lowercase letters, numbers, and hyphens" },
            length: { in: 3..63 }
  validate :subdomain_not_reserved

  # Reserved subdomains
  RESERVED_SUBDOMAINS = %w[
    www admin api app blog help support
    mail email ftp ssh git staging production
    about terms privacy security
  ].freeze

  def pending_invitations
    invitations.where(status: 'pending').where('expires_at > ?', Time.current)
  end

  def transfer_ownership_to(new_owner)
    raise ArgumentError, "New owner must be an admin" unless new_owner.admin?(self)

    ApplicationRecord.transaction do
      # Demote current owner to admin
      owner_membership.update!(role: 'ADMIN')

      # Promote new owner
      new_owner.membership_in(self).update!(role: 'OWNER')
    end
  end

  private

  def subdomain_not_reserved
    if subdomain.present? && RESERVED_SUBDOMAINS.include?(subdomain.downcase)
      errors.add(:subdomain, "is reserved")
    end
  end
end
```

### Organization Membership Model

```ruby
# app/models/organization_membership.rb
class OrganizationMembership < ApplicationRecord
  ROLES = %w[OWNER ADMIN SUPPORT_AGENT].freeze

  belongs_to :user
  belongs_to :organization

  validates :role, presence: true, inclusion: { in: ROLES }
  validates :user_id, uniqueness: { scope: :organization_id,
                                     message: "is already a member of this organization" }
  validate :only_one_owner_per_organization

  scope :owners, -> { where(role: 'OWNER') }
  scope :admins, -> { where(role: 'ADMIN') }
  scope :support_agents, -> { where(role: 'SUPPORT_AGENT') }

  def owner?
    role == 'OWNER'
  end

  def admin?
    role == 'ADMIN'
  end

  def support_agent?
    role == 'SUPPORT_AGENT'
  end

  def can_manage?
    owner? || admin?
  end

  private

  def only_one_owner_per_organization
    if role == 'OWNER' && organization.present?
      existing_owner = organization.organization_memberships
                                   .where(role: 'OWNER')
                                   .where.not(id: id)
                                   .exists?

      if existing_owner
        errors.add(:role, "organization already has an owner")
      end
    end
  end
end
```

### Invitation Model

```ruby
# app/models/invitation.rb
class Invitation < ApplicationRecord
  STATUSES = %w[pending accepted rejected expired].freeze
  INVITABLE_ROLES = %w[ADMIN SUPPORT_AGENT].freeze

  belongs_to :organization
  belongs_to :invited_by, class_name: 'User'

  validates :email, presence: true, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :role, presence: true, inclusion: { in: INVITABLE_ROLES }
  validates :token, presence: true, uniqueness: true
  validates :status, presence: true, inclusion: { in: STATUSES }
  validates :expires_at, presence: true

  validate :user_not_already_member
  validate :no_duplicate_pending_invitation

  before_validation :generate_token, on: :create
  before_validation :set_expiry, on: :create

  scope :pending, -> { where(status: 'pending') }
  scope :active, -> { pending.where('expires_at > ?', Time.current) }
  scope :expired, -> { pending.where('expires_at <= ?', Time.current) }

  def pending?
    status == 'pending'
  end

  def expired?
    expires_at <= Time.current
  end

  def accept!(user)
    return false unless user.email == email
    return false unless pending? && !expired?

    ApplicationRecord.transaction do
      organization.organization_memberships.create!(
        user: user,
        role: role
      )

      update!(status: 'accepted', responded_at: Time.current)
    end
  rescue ActiveRecord::RecordInvalid
    false
  end

  def reject!
    return false unless pending?

    update(status: 'rejected', responded_at: Time.current)
  end

  private

  def generate_token
    self.token ||= SecureRandom.urlsafe_base64(32)
  end

  def set_expiry
    self.expires_at ||= 7.days.from_now
  end

  def user_not_already_member
    if organization.present? && email.present?
      user = User.find_by(email: email)
      if user && organization.users.include?(user)
        errors.add(:email, "is already a member of this organization")
      end
    end
  end

  def no_duplicate_pending_invitation
    if organization.present? && email.present? && pending?
      duplicate = organization.invitations
                             .pending
                             .where(email: email)
                             .where.not(id: id)
                             .exists?

      if duplicate
        errors.add(:email, "already has a pending invitation")
      end
    end
  end
end
```

---

## Controllers

### Organizations Controller

```ruby
# app/controllers/organizations_controller.rb
class OrganizationsController < ApplicationController
  before_action :set_organization, only: [:show, :edit, :update, :destroy, :transfer_ownership]

  def index
    @organizations = policy_scope(Organization)
  end

  def show
    authorize @organization
    @members = @organization.organization_memberships.includes(:user)
  end

  def edit
    authorize @organization
  end

  def update
    authorize @organization

    if @organization.update(organization_params)
      redirect_to @organization, notice: 'Organization updated successfully'
    else
      render :edit
    end
  end

  def destroy
    authorize @organization

    @organization.destroy
    redirect_to organizations_path, notice: 'Organization deleted successfully'
  end

  def switch
    @organization = Organization.find(params[:id])
    authorize @organization, :switch?

    session[:current_organization_id] = @organization.id
    redirect_to organization_path(@organization), notice: "Switched to #{@organization.name}"
  end

  def transfer_ownership
    authorize @organization, :transfer_ownership?

    new_owner = @organization.users.find(params[:new_owner_id])

    if @organization.transfer_ownership_to(new_owner)
      redirect_to organization_path(@organization),
                  notice: 'Ownership transferred successfully'
    else
      redirect_to organization_path(@organization),
                  alert: 'Failed to transfer ownership'
    end
  rescue ArgumentError => e
    redirect_to organization_path(@organization), alert: e.message
  end

  private

  def set_organization
    @organization = Organization.find(params[:id])
  end

  def organization_params
    params.require(:organization).permit(:name, :subdomain)
  end
end
```

### Invitations Controller

```ruby
# app/controllers/invitations_controller.rb
class InvitationsController < ApplicationController
  skip_before_action :authenticate_user!, only: [:show]
  before_action :set_invitation, only: [:show, :accept, :reject, :destroy]

  def index
    @invitations = policy_scope(Invitation)
                     .where(organization: @current_organization)
                     .includes(:invited_by)
                     .order(created_at: :desc)
  end

  def show
    authorize @invitation if user_signed_in?
    # Public view for invitation preview
  end

  def new
    @invitation = @current_organization.invitations.build
    authorize @invitation
  end

  def create
    @invitation = @current_organization.invitations.build(invitation_params)
    @invitation.invited_by = current_user

    authorize @invitation

    if @invitation.save
      InvitationMailer.invite(@invitation).deliver_later
      redirect_to organization_invitations_path(@current_organization),
                  notice: 'Invitation sent successfully'
    else
      render :new
    end
  end

  def accept
    authorize @invitation

    if @invitation.accept!(current_user)
      redirect_to organization_path(@invitation.organization),
                  notice: 'Invitation accepted successfully'
    else
      redirect_to invitation_path(@invitation.token),
                  alert: 'Unable to accept invitation'
    end
  end

  def reject
    authorize @invitation

    if @invitation.reject!
      redirect_to root_path, notice: 'Invitation declined'
    else
      redirect_to invitation_path(@invitation.token),
                  alert: 'Unable to reject invitation'
    end
  end

  def destroy
    authorize @invitation

    @invitation.destroy
    redirect_to organization_invitations_path(@current_organization),
                notice: 'Invitation cancelled'
  end

  private

  def set_invitation
    @invitation = Invitation.find_by!(token: params[:id])
  end

  def invitation_params
    params.require(:invitation).permit(:email, :role)
  end
end
```

### Members Controller

```ruby
# app/controllers/members_controller.rb
class MembersController < ApplicationController
  before_action :set_membership, only: [:edit, :update, :destroy]

  def index
    @memberships = policy_scope(OrganizationMembership)
                     .where(organization: @current_organization)
                     .includes(:user)
                     .order(created_at: :asc)
  end

  def edit
    authorize @membership
  end

  def update
    authorize @membership

    if @membership.update(membership_params)
      redirect_to organization_members_path(@current_organization),
                  notice: 'Member role updated successfully'
    else
      render :edit
    end
  end

  def destroy
    authorize @membership

    @membership.destroy
    redirect_to organization_members_path(@current_organization),
                notice: 'Member removed successfully'
  end

  private

  def set_membership
    @membership = OrganizationMembership.find(params[:id])
  end

  def membership_params
    params.require(:organization_membership).permit(:role)
  end
end
```

---

## Views with DaisyUI

### Organization Switcher (Navbar)

```erb
<!-- app/views/shared/_navbar.html.erb -->
<div class="navbar bg-base-100 shadow-lg">
  <div class="flex-1">
    <a class="btn btn-ghost text-xl">Your App</a>
  </div>

  <div class="flex-none gap-2">
    <!-- Organization Switcher -->
    <div class="dropdown dropdown-end">
      <label tabindex="0" class="btn btn-ghost gap-2">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
        </svg>
        <%= @current_organization&.name || 'Select Organization' %>
        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
        </svg>
      </label>

      <ul tabindex="0" class="dropdown-content menu p-2 shadow bg-base-100 rounded-box w-64 mt-3">
        <% current_user.organizations.each do |org| %>
          <li>
            <%= link_to switch_organization_path(org), method: :post,
                        class: "#{'active' if org == @current_organization}" do %>
              <div class="flex flex-col items-start">
                <span class="font-semibold"><%= org.name %></span>
                <span class="text-xs opacity-60"><%= org.subdomain %></span>
              </div>
            <% end %>
          </li>
        <% end %>
      </ul>
    </div>

    <!-- User Menu -->
    <div class="dropdown dropdown-end">
      <label tabindex="0" class="btn btn-ghost btn-circle avatar">
        <div class="w-10 rounded-full bg-primary text-primary-content flex items-center justify-center">
          <%= current_user.first_name[0].upcase %>
        </div>
      </label>
      <ul tabindex="0" class="dropdown-content menu p-2 shadow bg-base-100 rounded-box w-52 mt-3">
        <li><%= link_to 'Profile', edit_user_registration_path %></li>
        <li><%= link_to 'Settings', '#' %></li>
        <li><%= link_to 'Sign out', destroy_user_session_path, method: :delete %></li>
      </ul>
    </div>
  </div>
</div>
```

### Members List

```erb
<!-- app/views/members/index.html.erb -->
<div class="container mx-auto p-6">
  <div class="flex justify-between items-center mb-6">
    <h1 class="text-3xl font-bold">Team Members</h1>

    <% if policy(Invitation).create? %>
      <%= link_to new_organization_invitation_path(@current_organization),
                  class: 'btn btn-primary gap-2' do %>
        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
          <path d="M8 9a3 3 0 100-6 3 3 0 000 6zM8 11a6 6 0 016 6H2a6 6 0 016-6zM16 7a1 1 0 10-2 0v1h-1a1 1 0 100 2h1v1a1 1 0 102 0v-1h1a1 1 0 100-2h-1V7z" />
        </svg>
        Invite Member
      <% end %>
    <% end %>
  </div>

  <div class="overflow-x-auto">
    <table class="table w-full">
      <thead>
        <tr>
          <th>Name</th>
          <th>Email</th>
          <th>Role</th>
          <th>Joined</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <% @memberships.each do |membership| %>
          <tr>
            <td>
              <div class="flex items-center gap-3">
                <div class="avatar placeholder">
                  <div class="bg-neutral text-neutral-content rounded-full w-12">
                    <span><%= membership.user.first_name[0] %><%= membership.user.last_name[0] %></span>
                  </div>
                </div>
                <div>
                  <div class="font-bold"><%= membership.user.full_name %></div>
                </div>
              </div>
            </td>
            <td><%= membership.user.email %></td>
            <td>
              <span class="badge <%= role_badge_class(membership.role) %>">
                <%= membership.role %>
              </span>
            </td>
            <td><%= membership.created_at.strftime('%b %d, %Y') %></td>
            <td>
              <div class="dropdown dropdown-end">
                <label tabindex="0" class="btn btn-ghost btn-sm">
                  <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                    <path d="M10 6a2 2 0 110-4 2 2 0 010 4zM10 12a2 2 0 110-4 2 2 0 010 4zM10 18a2 2 0 110-4 2 2 0 010 4z" />
                  </svg>
                </label>
                <ul tabindex="0" class="dropdown-content menu p-2 shadow bg-base-100 rounded-box w-52">
                  <% if policy(membership).update? %>
                    <li><%= link_to 'Change Role', edit_member_path(membership) %></li>
                  <% end %>

                  <% if policy(@current_organization).transfer_ownership? && membership.admin? %>
                    <li>
                      <%= link_to 'Make Owner',
                                  transfer_ownership_organization_path(@current_organization, new_owner_id: membership.user.id),
                                  method: :post,
                                  data: { confirm: 'Transfer ownership to this user? You will become an Admin.' } %>
                    </li>
                  <% end %>

                  <% if policy(membership).destroy? %>
                    <li>
                      <%= link_to 'Remove', member_path(membership),
                                  method: :delete,
                                  data: { confirm: 'Are you sure?' },
                                  class: 'text-error' %>
                    </li>
                  <% end %>
                </ul>
              </div>
            </td>
          </tr>
        <% end %>
      </tbody>
    </table>
  </div>
</div>
```

### Invitation Card

```erb
<!-- app/views/invitations/show.html.erb -->
<div class="min-h-screen flex items-center justify-center bg-base-200">
  <div class="card w-96 bg-base-100 shadow-xl">
    <div class="card-body">
      <% if @invitation.expired? %>
        <div class="alert alert-error">
          <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span>This invitation has expired</span>
        </div>
      <% else %>
        <h2 class="card-title">You're invited!</h2>

        <div class="space-y-2">
          <p><strong><%= @invitation.invited_by.full_name %></strong> has invited you to join:</p>
          <div class="bg-base-200 p-4 rounded-lg">
            <p class="text-xl font-bold"><%= @invitation.organization.name %></p>
            <p class="text-sm opacity-60"><%= @invitation.organization.subdomain %></p>
          </div>
          <p>Role: <span class="badge <%= role_badge_class(@invitation.role) %>"><%= @invitation.role %></span></p>
        </div>

        <% if user_signed_in? %>
          <div class="card-actions justify-end mt-4">
            <%= button_to 'Reject', reject_invitation_path(@invitation.token),
                          method: :post,
                          class: 'btn btn-error btn-outline' %>
            <%= button_to 'Accept', accept_invitation_path(@invitation.token),
                          method: :post,
                          class: 'btn btn-success' %>
          </div>
        <% else %>
          <div class="card-actions justify-center mt-4">
            <%= link_to 'Sign in to accept', new_user_session_path(invitation_token: @invitation.token),
                        class: 'btn btn-primary' %>
            <%= link_to 'Create account', new_user_registration_path(invitation_token: @invitation.token),
                        class: 'btn btn-ghost' %>
          </div>
        <% end %>
      <% end %>
    </div>
  </div>
</div>
```

### Helper Methods

```ruby
# app/helpers/application_helper.rb
module ApplicationHelper
  def role_badge_class(role)
    case role
    when 'OWNER'
      'badge-primary'
    when 'ADMIN'
      'badge-secondary'
    when 'SUPPORT_AGENT'
      'badge-accent'
    else
      'badge-ghost'
    end
  end
end
```

---

## Background Jobs

### Expire Invitations Job

```ruby
# app/jobs/expire_invitations_job.rb
class ExpireInvitationsJob < ApplicationJob
  queue_as :default

  def perform
    Invitation.pending.where('expires_at <= ?', Time.current).find_each do |invitation|
      invitation.update(status: 'expired')
    end
  end
end
```

### Schedule with Sidekiq

```ruby
# config/initializers/sidekiq.rb
require 'sidekiq/cron/job'

Sidekiq::Cron::Job.create(
  name: 'Expire Invitations - daily',
  cron: '0 0 * * *', # Every day at midnight
  class: 'ExpireInvitationsJob'
)
```

### Invitation Mailer

```ruby
# app/mailers/invitation_mailer.rb
class InvitationMailer < ApplicationMailer
  def invite(invitation)
    @invitation = invitation
    @organization = invitation.organization
    @invited_by = invitation.invited_by

    mail(
      to: @invitation.email,
      subject: "You've been invited to join #{@organization.name}"
    )
  end
end
```

```erb
<!-- app/views/invitation_mailer/invite.html.erb -->
<h1>You're invited to <%= @organization.name %>!</h1>

<p><%= @invited_by.full_name %> has invited you to join their organization as a <%= @invitation.role %>.</p>

<p>
  <%= link_to 'View Invitation', invitation_url(@invitation.token),
              style: 'background-color: #0066cc; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;' %>
</p>

<p><small>This invitation expires on <%= @invitation.expires_at.strftime('%B %d, %Y at %I:%M %p') %></small></p>
```

---

## Testing

### Policy Specs

```ruby
# spec/policies/organization_policy_spec.rb
require 'rails_helper'

RSpec.describe OrganizationPolicy do
  subject { described_class.new(context, organization) }

  let(:organization) { create(:organization) }
  let(:user) { create(:user) }
  let(:context) { CurrentContext.new(user, organization) }

  context 'when user is OWNER' do
    before do
      create(:organization_membership, user: user, organization: organization, role: 'OWNER')
    end

    it { is_expected.to permit_action(:show) }
    it { is_expected.to permit_action(:update) }
    it { is_expected.to permit_action(:update_subdomain) }
    it { is_expected.to permit_action(:destroy) }
    it { is_expected.to permit_action(:transfer_ownership) }
  end

  context 'when user is ADMIN' do
    before do
      create(:organization_membership, user: user, organization: organization, role: 'ADMIN')
    end

    it { is_expected.to permit_action(:show) }
    it { is_expected.to permit_action(:update) }
    it { is_expected.to permit_action(:update_subdomain) }
    it { is_expected.not_to permit_action(:destroy) }
    it { is_expected.not_to permit_action(:transfer_ownership) }
  end

  context 'when user is SUPPORT_AGENT' do
    before do
      create(:organization_membership, user: user, organization: organization, role: 'SUPPORT_AGENT')
    end

    it { is_expected.to permit_action(:show) }
    it { is_expected.not_to permit_action(:update) }
    it { is_expected.not_to permit_action(:destroy) }
  end

  context 'when user is not a member' do
    it { is_expected.not_to permit_action(:show) }
    it { is_expected.not_to permit_action(:update) }
    it { is_expected.not_to permit_action(:destroy) }
  end
end
```

### Model Specs

```ruby
# spec/models/organization_spec.rb
require 'rails_helper'

RSpec.describe Organization, type: :model do
  describe 'associations' do
    it { should have_many(:organization_memberships).dependent(:destroy) }
    it { should have_many(:users).through(:organization_memberships) }
    it { should have_many(:invitations).dependent(:destroy) }
    it { should have_one(:owner_membership) }
    it { should have_one(:owner) }
  end

  describe 'validations' do
    it { should validate_presence_of(:name) }
    it { should validate_presence_of(:subdomain) }
    it { should validate_uniqueness_of(:subdomain) }
    it { should validate_length_of(:subdomain).is_at_least(3).is_at_most(63) }
  end

  describe '#transfer_ownership_to' do
    let(:organization) { create(:organization) }
    let(:owner) { create(:user) }
    let(:admin) { create(:user) }

    before do
      create(:organization_membership, user: owner, organization: organization, role: 'OWNER')
      create(:organization_membership, user: admin, organization: organization, role: 'ADMIN')
    end

    it 'transfers ownership from current owner to admin' do
      organization.transfer_ownership_to(admin)

      expect(owner.reload.role_in(organization)).to eq('ADMIN')
      expect(admin.reload.role_in(organization)).to eq('OWNER')
    end

    it 'raises error if new owner is not an admin' do
      support_agent = create(:user)
      create(:organization_membership, user: support_agent, organization: organization, role: 'SUPPORT_AGENT')

      expect {
        organization.transfer_ownership_to(support_agent)
      }.to raise_error(ArgumentError)
    end
  end
end
```

### Integration Specs

```ruby
# spec/requests/invitations_spec.rb
require 'rails_helper'

RSpec.describe 'Invitations', type: :request do
  let(:organization) { create(:organization) }
  let(:owner) { create(:user) }
  let(:admin) { create(:user) }
  let(:support_agent) { create(:user) }

  before do
    create(:organization_membership, user: owner, organization: organization, role: 'OWNER')
    create(:organization_membership, user: admin, organization: organization, role: 'ADMIN')
    create(:organization_membership, user: support_agent, organization: organization, role: 'SUPPORT_AGENT')
  end

  describe 'POST /organizations/:organization_id/invitations' do
    context 'when user is owner' do
      before { sign_in owner }

      it 'creates an invitation' do
        expect {
          post organization_invitations_path(organization), params: {
            invitation: { email: 'newuser@example.com', role: 'ADMIN' }
          }
        }.to change(Invitation, :count).by(1)

        expect(response).to redirect_to(organization_invitations_path(organization))
      end
    end

    context 'when user is support agent' do
      before { sign_in support_agent }

      it 'denies access' do
        post organization_invitations_path(organization), params: {
          invitation: { email: 'newuser@example.com', role: 'ADMIN' }
        }

        expect(response).to redirect_to(root_path)
        expect(flash[:alert]).to be_present
      end
    end
  end
end
```

---

## Conclusion

This document provides practical code examples and patterns for implementing the multi-tenant SaaS application. Use these as templates and modify them according to your specific needs.

For the overall project structure and requirements, refer to [PROJECT_SPECIFICATION.md](PROJECT_SPECIFICATION.md).
