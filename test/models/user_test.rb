require "test_helper"

class UserTest < ActiveSupport::TestCase
  test "should be valid with valid attributes" do
    user = User.new(
      email: "test@example.com",
      password: "password123",
      first_name: "John",
      last_name: "Doe",
      phone_number: "5551234567",
      country_code: "+1"
    )
    assert user.valid?
  end

  test "should require first_name" do
    user = User.new(
      email: "test@example.com",
      password: "password123",
      last_name: "Doe",
      phone_number: "5551234567",
      country_code: "+1"
    )
    assert_not user.valid?
    assert_includes user.errors[:first_name], "can't be blank"
  end

  test "should require last_name" do
    user = User.new(
      email: "test@example.com",
      password: "password123",
      first_name: "John",
      phone_number: "5551234567",
      country_code: "+1"
    )
    assert_not user.valid?
    assert_includes user.errors[:last_name], "can't be blank"
  end

  test "should require phone_number" do
    user = User.new(
      email: "test@example.com",
      password: "password123",
      first_name: "John",
      last_name: "Doe",
      country_code: "+1"
    )
    assert_not user.valid?
    assert_includes user.errors[:phone_number], "can't be blank"
  end

  test "should require unique phone_number" do
    User.create!(
      email: "user1@example.com",
      password: "password123",
      first_name: "John",
      last_name: "Doe",
      phone_number: "5551234567",
      country_code: "+1"
    )

    user2 = User.new(
      email: "user2@example.com",
      password: "password123",
      first_name: "Jane",
      last_name: "Smith",
      phone_number: "5551234567",
      country_code: "+1"
    )

    assert_not user2.valid?
    assert_includes user2.errors[:phone_number], "has already been taken"
  end

  test "should have default country_code" do
    user = User.new(
      email: "test@example.com",
      password: "password123",
      first_name: "John",
      last_name: "Doe",
      phone_number: "5551234567"
    )
    assert_equal "+1", user.country_code
  end
end
