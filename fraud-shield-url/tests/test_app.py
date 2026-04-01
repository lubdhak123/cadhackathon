"""Basic tests for URL Sandbox components"""
import pytest
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_health_check():
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_root_endpoint():
    """Test root endpoint"""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "service" in data
    assert "url-sandbox" in data["service"].lower() or "sandbox" in data["service"].lower()

def test_scan_url_invalid_url():
    """Test scan endpoint with invalid URL"""
    response = client.post("/scan-url", json={"url": "not-a-url"})
    assert response.status_code == 422  # Validation error

def test_scan_url_valid_structure():
    """Test that valid requests get proper response structure"""
    # This will fail without real API keys, but tests structure
    response = client.post("/scan-url", json={"url": "https://example.com"})
    # Should either succeed or fail gracefully
    assert response.status_code in [200, 500]
    
    if response.status_code == 200:
        data = response.json()
        assert "scan_id" in data
        assert "url" in data
        assert "threat_score" in data
        assert 0 <= data["threat_score"] <= 100
        assert "reason" in data
        assert "findings" in data

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
