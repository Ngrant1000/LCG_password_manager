import unittest
from lcg_password_manager.password_strength import PasswordStrength

class TestPasswordStrength(unittest.TestCase):
    def setUp(self):
        self.password_strength = PasswordStrength()
        
    def test_basic_password_validation(self):
        """Test basic password validation rules"""
        # Test minimum length
        self.assertFalse(self.password_strength.is_valid("short"))
        self.assertTrue(self.password_strength.is_valid("longenough"))
        
        # Test character types
        self.assertFalse(self.password_strength.is_valid("nouppercase"))
        self.assertFalse(self.password_strength.is_valid("NOLOWERCASE"))
        self.assertFalse(self.password_strength.is_valid("NoNumbers"))
        self.assertFalse(self.password_strength.is_valid("NoSpecial1"))
        
        # Test valid password
        self.assertTrue(self.password_strength.is_valid("ValidPass1!"))
        
    def test_password_strength_scoring(self):
        """Test password strength scoring"""
        # Test weak password
        score = self.password_strength.calculate_strength("weak")
        self.assertLess(score, 50)
        
        # Test medium password
        score = self.password_strength.calculate_strength("MediumPass1")
        self.assertGreaterEqual(score, 50)
        self.assertLess(score, 80)
        
        # Test strong password
        score = self.password_strength.calculate_strength("StrongPass1!")
        self.assertGreaterEqual(score, 80)
        
    def test_common_password_detection(self):
        """Test detection of common passwords"""
        # Test common passwords
        self.assertTrue(self.password_strength.is_common_password("password123"))
        self.assertTrue(self.password_strength.is_common_password("qwerty"))
        
        # Test uncommon passwords
        self.assertFalse(self.password_strength.is_common_password("xK9#mP2$vL"))
        
    def test_password_pattern_detection(self):
        """Test detection of common patterns"""
        # Test sequential patterns
        self.assertTrue(self.password_strength.has_sequential_pattern("abc123"))
        self.assertTrue(self.password_strength.has_sequential_pattern("123456"))
        
        # Test keyboard patterns
        self.assertTrue(self.password_strength.has_keyboard_pattern("qwerty"))
        self.assertTrue(self.password_strength.has_keyboard_pattern("asdfgh"))
        
        # Test non-pattern passwords
        self.assertFalse(self.password_strength.has_sequential_pattern("xK9#mP2$vL"))
        self.assertFalse(self.password_strength.has_keyboard_pattern("xK9#mP2$vL"))
        
    def test_password_entropy(self):
        """Test password entropy calculation"""
        # Test low entropy password
        entropy = self.password_strength.calculate_entropy("password")
        self.assertLess(entropy, 40)
        
        # Test medium entropy password
        entropy = self.password_strength.calculate_entropy("Password123")
        self.assertGreaterEqual(entropy, 40)
        self.assertLess(entropy, 60)
        
        # Test high entropy password
        entropy = self.password_strength.calculate_entropy("xK9#mP2$vL")
        self.assertGreaterEqual(entropy, 60)
        
    def test_password_recommendations(self):
        """Test password recommendations"""
        # Test weak password recommendations
        recommendations = self.password_strength.get_recommendations("weak")
        self.assertIn("length", recommendations)
        self.assertIn("uppercase", recommendations)
        self.assertIn("numbers", recommendations)
        
        # Test medium password recommendations
        recommendations = self.password_strength.get_recommendations("MediumPass1")
        self.assertIn("special", recommendations)
        
        # Test strong password recommendations
        recommendations = self.password_strength.get_recommendations("StrongPass1!")
        self.assertEqual(len(recommendations), 0)
        
    def test_password_history(self):
        """Test password history validation"""
        # Add passwords to history
        self.password_strength.add_to_history("OldPass1!")
        self.password_strength.add_to_history("OldPass2!")
        
        # Test password reuse
        self.assertTrue(self.password_strength.is_password_reused("OldPass1!"))
        self.assertFalse(self.password_strength.is_password_reused("NewPass1!"))
        
    def test_password_expiration(self):
        """Test password expiration checks"""
        # Test expired password
        self.assertTrue(self.password_strength.is_password_expired("OldPass1!", days=90))
        
        # Test valid password
        self.assertFalse(self.password_strength.is_password_expired("NewPass1!", days=30))
        
    def test_password_complexity_requirements(self):
        """Test password complexity requirements"""
        # Test minimum requirements
        requirements = self.password_strength.get_complexity_requirements()
        self.assertIn("min_length", requirements)
        self.assertIn("require_uppercase", requirements)
        self.assertIn("require_numbers", requirements)
        self.assertIn("require_special", requirements)
        
        # Test custom requirements
        custom_requirements = {
            "min_length": 12,
            "require_uppercase": True,
            "require_numbers": True,
            "require_special": True
        }
        self.password_strength.set_complexity_requirements(custom_requirements)
        
        # Verify custom requirements
        self.assertFalse(self.password_strength.is_valid("short"))
        self.assertTrue(self.password_strength.is_valid("LongPass1!"))
        
if __name__ == '__main__':
    unittest.main() 