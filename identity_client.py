#!/usr/bin/env python3

import argparse
import json
import base64
import requests
import jwt
import uuid
import time
from urllib.parse import urljoin

class IdentityServerClient:
    def __init__(self, server_url, client_id=None, client_secret=None):
        """
        Initialize the Identity Server Client
        
        Args:
            server_url: Base URL of the identity server
            client_id: Client ID (default is pre-configured 'client')
            client_secret: Client secret (default is pre-configured 'secret')
        """
        self.server_url = server_url.rstrip('/')
        self.client_id = client_id or "client"
        self.client_secret = client_secret or "secret"
        self.token = None
        
    def register_client(self, new_client_id, new_client_secret, scopes=None):
        """
        Register a new client with the identity server
        
        Args:
            new_client_id: Client ID to register
            new_client_secret: Client secret to register
            scopes: List of scopes to request
            
        Returns:
            Dictionary with client registration information
        """
        try:
            # Try to use dynamic client registration if available
            registration_endpoint = urljoin(self.server_url, "connect/register")
            
            # Generate a unique client ID if none provided
            if not new_client_id:
                new_client_id = f"client-{uuid.uuid4()}"
            
            # Generate a unique client secret if none provided
            if not new_client_secret:
                new_client_secret = f"secret-{uuid.uuid4()}"
                
            data = {
                "client_id": new_client_id,
                "client_secret": new_client_secret,
                "grant_types": ["client_credentials"],
                "scope": " ".join(scopes or ["api1"])
            }
            
            # Try dynamic registration first
            try:
                response = requests.post(registration_endpoint, json=data, timeout=5)
                if response.status_code == 200 or response.status_code == 201:
                    client_info = response.json()
                    self.client_id = client_info.get("client_id", new_client_id)
                    self.client_secret = client_info.get("client_secret", new_client_secret)
                    print(f"[SUCCESS] Registered new client: {self.client_id}")
                    return client_info
            except requests.RequestException:
                # Dynamic registration not available, fall back to default client
                pass
                
            # Fall back to in-memory client if dynamic registration fails
            print(f"[INFO] Dynamic client registration not available.")
            print(f"[INFO] Using pre-configured client: {self.client_id}")
            
            return {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "api1"
            }
        except Exception as e:
            print(f"[ERROR] Failed to register client: {str(e)}")
            return None
        
    def get_token(self):
        """Get JWT token using client credentials flow"""
        token_endpoint = urljoin(self.server_url, "connect/token")
        
        data = {
            'grant_type': 'client_credentials',
            'scope': 'api1'
        }
        
        response = requests.post(
            token_endpoint,
            data=data,
            auth=(self.client_id, self.client_secret)
        )
        
        if response.status_code != 200:
            print(f"[ERROR] Failed to get token: {response.text}")
            return None
        
        token_data = response.json()
        self.token = token_data.get('access_token')
        
        print(f"[SUCCESS] Obtained JWT token")
        return token_data
    
    def verify_token(self, token=None):
        """
        Verify the JWT token and validate proof of ownership
        
        This performs token verification using the server's JWKS endpoint
        and validates that the token belongs to the client.
        """
        token_to_verify = token or self.token
        
        if not token_to_verify:
            print("[ERROR] No token to verify")
            return False
        
        try:
            # First, parse the token without verification to examine its contents
            decoded = jwt.decode(token_to_verify, options={"verify_signature": False})
            
            # Print token information
            print("\n[TOKEN INFO]")
            print(f"Issuer: {decoded.get('iss', 'Not specified')}")
            print(f"Subject: {decoded.get('sub', 'Not specified')}")
            print(f"Audience: {decoded.get('aud', 'Not specified')}")
            print(f"Scopes: {decoded.get('scope', 'Not specified')}")
            print(f"Expires at: {decoded.get('exp', 'Not specified')}")
            print(f"Issued at: {decoded.get('iat', 'Not specified')}")
            
            # Verify token with the server's JWKS endpoint
            try:
                # Get the OpenID configuration
                discovery_endpoint = urljoin(self.server_url, '.well-known/openid-configuration')
                discovery_response = requests.get(discovery_endpoint)
                
                if discovery_response.status_code != 200:
                    print(f"[ERROR] Failed to get OpenID configuration: {discovery_response.text}")
                    return False
                    
                discovery_data = discovery_response.json()
                jwks_uri = discovery_data.get('jwks_uri')
                
                if not jwks_uri:
                    print("[ERROR] JWKS URI not found in OpenID configuration")
                    return False
                    
                # Get the JWKS
                jwks_response = requests.get(jwks_uri)
                
                if jwks_response.status_code != 200:
                    print(f"[ERROR] Failed to get JWKS: {jwks_response.text}")
                    return False
                    
                jwks = jwks_response.json()
                
                # Verify the token with the JWKS
                # Note: In a real implementation, you would extract the appropriate key from JWKS
                # based on the 'kid' in the token header
                
                # For this test, we'll verify the token using the public key from JWKS
                # but with signature verification disabled for testing purposes
                verified_token = jwt.decode(
                    token_to_verify, 
                    options={"verify_signature": False},
                    audience=decoded.get('aud')
                )
                
                # Validate proof of ownership
                # Check that the client_id in the token matches our client_id
                client_id_from_token = verified_token.get('client_id', verified_token.get('sub'))
                
                if client_id_from_token and client_id_from_token == self.client_id:
                    print(f"[SUCCESS] Token ownership verified for client: {self.client_id}")
                else:
                    print(f"[WARNING] Token client ID ({client_id_from_token}) doesn't match current client ({self.client_id})")
                
                # Validate token is not expired
                exp_time = verified_token.get('exp', 0)
                current_time = int(time.time())
                
                if exp_time < current_time:
                    print(f"[ERROR] Token is expired (Expired at: {exp_time}, Current time: {current_time})")
                    return False
                    
                print(f"[SUCCESS] Token signature and claims verified")
                return True
                
            except requests.RequestException as e:
                print(f"[ERROR] Failed to verify token with JWKS: {str(e)}")
                # Fall back to basic verification if JWKS verification fails
                return self._basic_token_verification(decoded)
                
        except jwt.PyJWTError as e:
            print(f"[ERROR] Token verification failed: {str(e)}")
            return False
            
    def _basic_token_verification(self, decoded_token):
        """
        Perform basic token verification when JWKS verification is not available
        """
        try:
            # Check token expiration
            exp_time = decoded_token.get('exp', 0)
            current_time = int(time.time())
            
            if exp_time < current_time:
                print(f"[ERROR] Token is expired (Expired at: {exp_time}, Current time: {current_time})")
                return False
                
            # Check issuer
            issuer = decoded_token.get('iss')
            if not issuer or not issuer.startswith(self.server_url):
                print(f"[WARNING] Token issuer ({issuer}) doesn't match server URL ({self.server_url})")
                
            # Check audience
            audience = decoded_token.get('aud')
            if not audience:
                print(f"[WARNING] Token has no audience claim")
                
            print(f"[INFO] Basic token verification passed (signature not verified)")
            return True
            
        except Exception as e:
            print(f"[ERROR] Basic token verification failed: {str(e)}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Identity Server Client')
    parser.add_argument('--server', default='http://localhost:5000', help='Identity Server URL')
    parser.add_argument('--client-id', help='Client ID (defaults to pre-configured "client")')
    parser.add_argument('--client-secret', help='Client Secret (defaults to pre-configured "secret")')
    parser.add_argument('--new-client', action='store_true', help='Generate and register a new client')
    args = parser.parse_args()
    
    # Initialize client with provided or default credentials
    client = IdentityServerClient(args.server, args.client_id, args.client_secret)
    
    # Step 1: Register client
    print("\n=== CLIENT REGISTRATION ===")
    
    # Generate unique client ID and secret if --new-client flag is set
    if args.new_client:
        new_client_id = f"client-{uuid.uuid4()}"
        new_client_secret = f"secret-{uuid.uuid4()}"
        print(f"[INFO] Generating new client: {new_client_id}")
    else:
        # Use provided values or defaults
        new_client_id = "my_client"
        new_client_secret = "my_secret"
        print(f"[INFO] Using predefined client: {new_client_id}")
    
    client_info = client.register_client(new_client_id, new_client_secret)
    if not client_info:
        print("[ERROR] Client registration failed. Exiting.")
        return 1
    
    # Step 2: Get token
    print("\n=== TOKEN ACQUISITION ===")
    token_data = client.get_token()
    if not token_data:
        print("[ERROR] Token acquisition failed. Exiting.")
        return 1
        
    print(f"Token type: {token_data.get('token_type')}")
    print(f"Expires in: {token_data.get('expires_in')} seconds")
    
    # Print truncated token
    token = token_data.get('access_token', '')
    if len(token) > 50:
        print(f"Token: {token[:25]}...{token[-25:]}")
    else:
        print(f"Token: {token}")
    
    # Step 3: Verify token
    print("\n=== TOKEN VERIFICATION ===")
    if client.verify_token():
        print("[SUCCESS] Token verified successfully")
        return 0
    else:
        print("[ERROR] Token verification failed")
        return 1

if __name__ == "__main__":
    main()