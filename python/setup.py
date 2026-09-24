#!/usr/bin/env python3
"""
Setup script for Python environment validation and dependency installation.

Usage:
    python setup.py
"""

import sys
import subprocess
import os


def check_python_version():
    """Ensure Python 3.10+"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        print(f"❌ Python 3.10+ required. Found: {version.major}.{version.minor}")
        sys.exit(1)
    print(f"✓ Python {version.major}.{version.minor}.{version.micro}")


def install_dependencies():
    """Install Python packages from requirements.txt"""
    print("\n📦 Installing Python dependencies...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✓ Dependencies installed")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        sys.exit(1)


def verify_imports():
    """Test critical imports"""
    print("\n🔍 Verifying imports...")
    
    critical_packages = [
        ('numpy', 'NumPy'),
        ('scipy', 'SciPy'),
        ('requests', 'Requests'),
        ('psycopg2', 'psycopg2'),
        ('sentence_transformers', 'Sentence Transformers'),
        ('chromadb', 'ChromaDB'),
        ('langchain', 'LangChain'),
        ('langgraph', 'LangGraph'),
        ('pulp', 'PuLP'),
    ]
    
    failed = []
    
    for module, name in critical_packages:
        try:
            __import__(module)
            print(f"  ✓ {name}")
        except ImportError:
            print(f"  ❌ {name}")
            failed.append(name)
    
    if failed:
        print(f"\n❌ Missing packages: {', '.join(failed)}")
        print("Run: pip install -r requirements.txt")
        sys.exit(1)


def check_ollama():
    """Check if Ollama is available (optional)"""
    print("\n🦙 Checking Ollama availability (optional)...")
    try:
        import requests
        response = requests.get('http://localhost:11434/api/tags', timeout=2)
        if response.ok:
            print("  ✓ Ollama is running")
            models = response.json().get('models', [])
            if models:
                print(f"  Available models: {[m['name'] for m in models]}")
            else:
                print("  ⚠ No models installed. Run: ollama pull llama3.1:8b")
        else:
            print("  ⚠ Ollama not running")
    except Exception:
        print("  ⚠ Ollama not detected (optional - Claude API can be used instead)")


def check_database():
    """Check database connectivity (optional)"""
    print("\n🗄️  Checking database connection (optional)...")
    try:
        from dotenv import load_dotenv
        load_dotenv('../.env')
        
        database_url = os.getenv('DATABASE_URL')
        if not database_url:
            print("  ⚠ DATABASE_URL not set in .env")
            return
        
        import psycopg2
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        print(f"  ✓ PostgreSQL connected: {version[:50]}...")
        conn.close()
        
    except Exception as e:
        print(f"  ⚠ Database connection failed: {e}")


def main():
    """Run all setup checks"""
    print("="*60)
    print("CyberRisk AI - Python Environment Setup")
    print("="*60)
    
    check_python_version()
    
    if '--install' in sys.argv:
        install_dependencies()
    
    verify_imports()
    check_ollama()
    check_database()
    
    print("\n" + "="*60)
    print("✅ Setup complete! Python agents are ready.")
    print("="*60)
    print("\nNext steps:")
    print("1. Configure .env file with DATABASE_URL")
    print("2. (Optional) Install Ollama: https://ollama.ai/download")
    print("3. Run: python orchestrator.py")
    print()


if __name__ == '__main__':
    main()
