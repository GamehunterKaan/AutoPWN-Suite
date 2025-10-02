"""
Validation tests to ensure the testing infrastructure is properly set up.
"""
import sys
import pytest
from pathlib import Path


class TestSetupValidation:
    """Validate that the testing infrastructure is properly configured."""
    
    @pytest.mark.unit
    def test_project_imports(self):
        """Test that main project modules can be imported."""
        # Test importing main modules
        import autopwn
        import api
        import modules
        
        # Verify modules are loaded from correct path
        project_root = Path(__file__).parent.parent
        assert Path(autopwn.__file__).parent == project_root
        assert Path(api.__file__).parent == project_root
        
    @pytest.mark.unit
    def test_pytest_markers(self, request):
        """Test that custom pytest markers are registered."""
        # Check that our custom markers exist
        markers = request.config.getini("markers")
        marker_names = [m.split(":")[0].strip() for m in markers]
        
        assert "unit" in marker_names
        assert "integration" in marker_names
        assert "slow" in marker_names
    
    @pytest.mark.unit
    def test_fixtures_available(self, temp_dir, mock_config, sample_vulnerability_data):
        """Test that key fixtures are available and working."""
        # Test temp_dir fixture
        assert temp_dir.exists()
        assert temp_dir.is_dir()
        
        # Test mock_config fixture
        assert mock_config.target == "192.168.1.1"
        assert mock_config.port == 80
        
        # Test sample data fixture
        assert "CVE-2021-44228" in sample_vulnerability_data
        assert sample_vulnerability_data["CVE-2021-44228"]["severity"] == "CRITICAL"
    
    @pytest.mark.unit
    def test_temp_file_fixture(self, temp_file):
        """Test the temp_file fixture functionality."""
        # Create a test file
        test_content = "Hello, testing!"
        test_path = temp_file("test.txt", test_content)
        
        assert test_path.exists()
        assert test_path.read_text() == test_content
    
    @pytest.mark.unit
    def test_mock_fixtures(self, mock_scanner, mock_http_response):
        """Test that mock fixtures work correctly."""
        # Test mock scanner
        result = mock_scanner.scan()
        assert "scan" in result
        assert "192.168.1.1" in result["scan"]
        
        # Test mock HTTP response
        response = mock_http_response(200, "OK")
        assert response.status_code == 200
        assert response.text == "OK"
    
    @pytest.mark.unit
    def test_coverage_import(self):
        """Test that coverage tools are available."""
        import coverage
        import pytest_cov
        
        # Verify coverage is properly installed
        assert hasattr(coverage, "Coverage")
    
    @pytest.mark.integration
    def test_project_structure(self):
        """Test that the project structure is correct."""
        project_root = Path(__file__).parent.parent
        
        # Check main directories exist
        assert (project_root / "modules").exists()
        assert (project_root / "modules" / "web").exists()
        assert (project_root / "tests").exists()
        assert (project_root / "tests" / "unit").exists()
        assert (project_root / "tests" / "integration").exists()
        
        # Check main files exist
        assert (project_root / "autopwn.py").exists()
        assert (project_root / "api.py").exists()
        assert (project_root / "requirements.txt").exists()
        assert (project_root / "pyproject.toml").exists()
    
    @pytest.mark.unit 
    def test_captured_output_fixture(self, capsys):
        """Test that output can be captured (using built-in capsys)."""
        print("Test stdout")
        sys.stderr.write("Test stderr")
        
        captured = capsys.readouterr()
        
        assert "Test stdout" in captured.out
        assert "Test stderr" in captured.err
    
    @pytest.mark.slow
    def test_slow_marker(self):
        """Test that the slow marker works (this test is marked as slow)."""
        import time
        # Simulate a slow operation
        time.sleep(0.1)
        assert True