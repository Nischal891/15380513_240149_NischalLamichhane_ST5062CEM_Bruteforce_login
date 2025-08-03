import unittest
from unittest.mock import patch, mock_open
import brute_forcing  # main script


class TestBruteForcing(unittest.TestCase):

    def setUp(self):
        # Reset global flag before each test
        brute_forcing.found_creds = False

    def test_open_resources_success(self):
        with patch("builtins.open", mock_open(read_data="user1\nuser2\npass1\npass2")):
            result = brute_forcing.open_resources("test_file.txt")
            self.assertEqual(result, ["user1", "user2", "pass1", "pass2"])

    def test_open_resources_exception(self):
        with patch("builtins.open", side_effect=Exception("File error")):
            result = brute_forcing.open_resources("bad_file.txt")
            self.assertIsNone(result)

    def test_handle_success(self):
        # Initially should be False
        self.assertFalse(brute_forcing.found_creds)
        
        # Call handle_success
        brute_forcing.handle_success("admin", "password123")
        
        # Should now be True
        self.assertTrue(brute_forcing.found_creds)



    @patch("requests.get")
    def test_extract_form_fields_success(self, mock_get):
        mock_get.return_value.text = '''
        <form>
            <input name="username" type="text">
            <input name="password" type="password">
        </form>
        '''
        user_field, pass_field = brute_forcing.extract_form_fields("http://example.com")
        self.assertEqual(user_field, "username")
        self.assertEqual(pass_field, "password")

    @patch("requests.get")
    def test_extract_form_fields_failure_no_form(self, mock_get):
        mock_get.return_value.text = '<div>No form here</div>'
        user_field, pass_field = brute_forcing.extract_form_fields("http://example.com")
        self.assertIsNone(user_field)
        self.assertIsNone(pass_field)


if __name__ == '__main__':
    unittest.main()