#!/bin/bash

echo "Installing Python dependencies..."
pip install fastapi uvicorn sqlalchemy pydantic pydantic-settings pulp scikit-learn numpy joblib

echo "Installing Node dependencies..."
npm install

echo "Starting Backend in the background..."
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

echo "Waiting for Backend to be healthy..."
while ! curl -s http://localhost:8000/api/health | grep "healthy"; do
  echo "Backend not ready, waiting..."
  sleep 2
done

echo "Backend is healthy! Starting Frontend..."
npm run dev
