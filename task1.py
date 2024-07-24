import re

def check_password_strength(password):
  """Checks the strength of a password based on length, complexity, and uniqueness.

  Args:
    password: The password to be evaluated.

  Returns:
    A string indicating the password strength (weak, medium, strong, very strong).
  """

  # Minimum password length
  min_length = 8

  # Regular expressions for different character types
  has_upper = re.compile(r'[A-Z]')
  has_lower = re.compile(r'[a-z]')
  has_digit = re.compile(r'\d')
  has_special = re.compile(r'[^\w\s]')

  # Check password length
  if len(password) < min_length:
    return "Weak"

  # Check for character types
  strength = 0
  strength += 1 if has_upper.search(password) else 0
  strength += 1 if has_lower.search(password) else 0
  strength += 1 if has_digit.search(password) else 0
  strength += 1 if has_special.search(password) else 0

  # Assign strength level based on number of character types
  if strength == 1:
    return "Weak"
  elif strength == 2:
    return "Medium"
  elif strength == 3:
    return "Strong"
  else:
    return "Very Strong"

# Example usage
password = input("Enter a password: ")
strength = check_password_strength(password)
print("Password strength:", strength)
