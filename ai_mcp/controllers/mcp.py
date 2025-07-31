from odoo import http
from odoo.http import request
import json
import time
import logging
import requests
from datetime import datetime
import xml.etree.ElementTree as ET


class MCPController(http.Controller):
    """Controller for MCP (Model Context Protocol) endpoints."""
    
    @http.route("/mcp/models", type='http', auth='bearer', methods=['GET'], csrf=False)
    def get_models(self, **kwargs):
        """
        GET endpoint to retrieve available models based on user permissions.
        
        Returns:
            JSON response with list of available models and their metadata
            filtered by user's ai_mcp permissions.
        """
        try:
            # Get current user
            user = request.env.user
            
            # Get user's model permissions from ai_mcp system
            user_permissions = request.env['ai_mcp.model_permission'].sudo().search([
                ('user_id', '=', user.id),
                ('active', '=', True)
            ])
            
            # If user has no specific permissions, return empty list
            if not user_permissions:
                return json.dumps({
                    'status': 'success',
                    'data': {
                        'models': [],
                        'total_count': 0,
                        'message': 'No model permissions found for this user'
                    }
                }, indent=2)
            
            models_data = []
            for permission in user_permissions:
                model = permission.model_id
                if model:
                    models_data.append({
                        'model': model.model,
                        'name': model.name,
                        "operations": {
                            "read": permission.perm_read,
                            "write": permission.perm_write,
                            "create": permission.perm_create,
                            "delete": permission.perm_unlink,
                            "unlink": permission.perm_unlink
                        }
                    })
            
            return json.dumps({
                'success': True,
                'status': 'success',
                'data': {
                    'models': models_data,
                    'total_count': len(models_data),
                }
            }, indent=2)
            
        except Exception as e:
            return json.dumps({
                'success': False,
                'status': 'error',
                'message': str(e)
            }, indent=2)

    @http.route("/mcp/models/<model>/access", type='http', auth='bearer', methods=['GET'], csrf=False)
    def get_model_access(self, model, **kwargs):
        """
        GET endpoint to check access permissions for a specific model using ai_mcp permissions.
        
        Args:
            model (str): The model name to check access for.
            
        Returns:
            JSON response with access permissions information from ai_mcp system.
        """
        try:
            # Validate model exists
            model_record = request.env['ir.model'].sudo().search([('model', '=', model)], limit=1)
            if not model_record:
                return json.dumps({
                    'status': 'error',
                    'message': f'Model "{model}" not found'
                }, indent=2)
            
            # Get current user
            user = request.env.user
            
            # Get user's specific permission for this model from ai_mcp system
            permission = request.env['ai_mcp.model_permission'].sudo().search([
                ('user_id', '=', user.id),
                ('model_name', '=', model),
                ('active', '=', True)
            ], limit=1)
            
            # Build access information
            access_info = {
                'model': model,
                'enabled': False,
                'operations': {
                    'read': False,
                    'write': False,
                    'create': False,
                    'delete': False,
                    'unlink': False
                },
            }
            
            # If user has ai_mcp permission for this model
            if permission:
                access_info['operations'] = {
                    'read': permission.perm_read,
                    'write': permission.perm_write,
                    'create': permission.perm_create,
                    'delete': permission.perm_unlink,
                    'unlink': permission.perm_unlink
                }
                access_info['enabled'] = True
            
            return json.dumps({
                'success': True,
                'status': 'success',
                'data': access_info
            }, indent=2)
            
        except Exception as e:
            return json.dumps({
                'success': False,
                'status': 'error',
                'message': str(e)
            }, indent=2)

    # ------------------------------------------------------------------
    # /mcp/auth/validate - API Key validation
    # ------------------------------------------------------------------

    # Simple in-memory rate-limiting structures (per process)
    _RATE_LIMIT = {}
    _RATE_LIMIT_WINDOW = 60         # seconds
    _RATE_LIMIT_MAX_REQUESTS = 30   # max requests per IP within window

    @http.route("/mcp/auth/validate",
                type='http',
                auth='none',
                methods=['GET'],
                csrf=False)
    def validate_api_key(self, **kwargs):
        """Validate an API key via the `X-API-Key` header.

        OpenAPI behaviour:
            200 – key is valid
            401 – key missing or invalid
            429 – too many requests
        """
        # --------------------------------------------------------------
        # 1. Rate limiting (naive, in-memory)
        # --------------------------------------------------------------
        remote_addr = request.httprequest.remote_addr or 'unknown'
        now = time.time()

        timestamps = self._RATE_LIMIT.get(remote_addr, [])
        # Keep only timestamps within the current window
        timestamps = [ts for ts in timestamps if now - ts < self._RATE_LIMIT_WINDOW]
        timestamps.append(now)
        self._RATE_LIMIT[remote_addr] = timestamps

        if len(timestamps) > self._RATE_LIMIT_MAX_REQUESTS:
            payload = {
                'success': False,
                'data': {
                    'valid': False
                }
            }
            return request.make_json_response(payload, status=429)

        # --------------------------------------------------------------
        # 2. Extract and verify API key
        # --------------------------------------------------------------
        api_key = request.httprequest.headers.get('X-API-Key')
        if not api_key:
            payload = {
                'success': False,
                'data': {
                    'valid': False
                }
            }
            return request.make_json_response(payload, status=401)

        try:
            uid = request.env['res.users.apikeys']._check_credentials(scope='rpc', key=api_key)
        except Exception:
            uid = False

        # --------------------------------------------------------------
        # 3. Build and return response
        # --------------------------------------------------------------
        if uid:
            payload = {
                'success': True,
                'data': {
                    'valid': True,
                    'user_id': uid
                }
            }
            return request.make_json_response(payload, status=200)

        payload = {
            'success': False,
            'data': {
                'valid': False
            }
        }
        return request.make_json_response(payload, status=401)

    # ------------------------------------------------------------------
    # /mcp/xmlrpc/object - XML-RPC Proxy Endpoint Helper Methods
    # ------------------------------------------------------------------
    
    def _parse_xmlrpc_request(self, request_data):
        """
        Parse XML-RPC request to extract model and method information.
        
        Args:
            request_data (bytes): Raw XML-RPC request data
            
        Returns:
            dict: Parsed request information containing model, method, etc.
        """
        try:
            # Parse XML
            root = ET.fromstring(request_data.decode('utf-8'))
            
            # Find methodCall
            method_call = root.find('.//methodName')
            if method_call is None:
                return {'error': 'No methodName found in XML-RPC request'}
                
            method_name = method_call.text
            
            # Extract parameters
            params = []
            param_elements = root.findall('.//param/value')
            for param_elem in param_elements:
                # Try to extract string values (most common)
                string_elem = param_elem.find('./string')
                if string_elem is not None:
                    params.append(string_elem.text)
                # Try to extract int values
                int_elem = param_elem.find('./int') or param_elem.find('./i4')
                if int_elem is not None:
                    params.append(int(int_elem.text))
                # For other types, just append a placeholder
                if string_elem is None and int_elem is None:
                    params.append(None)
            
            # Typical Odoo XML-RPC structure: 
            # execute(db, uid, password, model, method, *args)
            # execute_kw(db, uid, password, model, method, args, kwargs)
            
            parsed_info = {
                'xmlrpc_method': method_name,
                'params': params,
                'model': None,
                'odoo_method': None,
                'database': None,
                'user_id': None
            }
            
            if method_name in ['execute', 'execute_kw'] and len(params) >= 5:
                parsed_info['database'] = params[0] if params[0] else None
                parsed_info['user_id'] = params[1] if isinstance(params[1], int) else None
                # params[2] is password, skip it
                parsed_info['model'] = params[3] if params[3] else None
                parsed_info['odoo_method'] = params[4] if params[4] else None
            
            return parsed_info
            
        except ET.ParseError as e:
            return {'error': f'Invalid XML format: {str(e)}'}
        except Exception as e:
            return {'error': f'Error parsing XML-RPC request: {str(e)}'}
    
    def _map_method_to_permission(self, odoo_method):
        """
        Map Odoo method to required permission type.
        
        Args:
            odoo_method (str): Odoo model method name
            
        Returns:
            str: Permission type ('read', 'write', 'create', 'unlink') or None
        """
        if not odoo_method:
            return None
            
        # Map common Odoo methods to CRUD permissions
        method_permission_map = {
            # Read operations
            'search': 'read',
            'search_read': 'read',
            'read': 'read',
            'browse': 'read',
            'get': 'read',
            'fields_get': 'read',
            'search_count': 'read',
            'name_search': 'read',
            'name_get': 'read',
            
            # Write operations
            'write': 'write',
            'update': 'write',
            
            # Create operations
            'create': 'create',
            'copy': 'create',
            
            # Delete operations
            'unlink': 'unlink',
            'delete': 'unlink',
        }
        
        # Direct match
        if odoo_method in method_permission_map:
            return method_permission_map[odoo_method]
        
        # Check for method prefixes
        for method_prefix, permission in method_permission_map.items():
            if odoo_method.startswith(method_prefix):
                return permission
        
        # Default to read permission for unknown methods
        return 'read'
    
    def _check_ai_mcp_permissions(self, user, model_name, permission_type):
        """
        Check if user has ai_mcp permissions for the specified model and operation.
        
        Args:
            user: Odoo user record
            model_name (str): Model name to check
            permission_type (str): Permission type ('read', 'write', 'create', 'unlink')
            
        Returns:
            dict: Permission check result with 'allowed' boolean and 'message'
        """
        try:
            if not model_name or not permission_type:
                return {
                    'allowed': False,
                    'message': 'Invalid model name or permission type'
                }
            
            # Get user's permissions using the existing method
            permission_model = request.env['ai_mcp.model_permission']
            permissions = permission_model.get_user_permissions(user.id, model_name)
            
            # Check the specific permission
            has_permission = permissions.get(permission_type, False)
            
            if has_permission:
                return {
                    'allowed': True,
                    'message': f'User has {permission_type} permission for {model_name}'
                }
            else:
                return {
                    'allowed': False,
                    'message': f'Access denied: User lacks {permission_type} permission for model {model_name}'
                }
                
        except Exception as e:
            return {
                'allowed': False,
                'message': f'Error checking permissions: {str(e)}'
            }
    
    def _create_xmlrpc_fault_response(self, fault_code, fault_string):
        """
        Create a standard XML-RPC fault response.
        
        Args:
            fault_code (int): Fault code
            fault_string (str): Fault message
            
        Returns:
            str: XML-RPC fault response
        """
        return f"""<?xml version="1.0"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>{fault_code}</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>{fault_string}</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>"""

    # ------------------------------------------------------------------
    # /mcp/xmlrpc/object - XML-RPC Proxy Endpoint
    # ------------------------------------------------------------------
    
    @http.route("/mcp/xmlrpc/object", 
                type='http', 
                auth='bearer', 
                methods=['POST'], 
                csrf=False)
    def xmlrpc_object_proxy(self, **kwargs):
        """
        Proxy endpoint for XML-RPC object calls.
        
        Intercepts requests that would normally go to /xmlrpc/2/object,
        applies ai_mcp permission controls, and forwards approved requests.
        
        This is a basic implementation that logs requests and forwards them
        to the original XML-RPC endpoint.
        """
        try:
            # Log the incoming request
            user = request.env.user
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            print(f"\n{'='*60}")
            print(f"[MCP PROXY] Incoming XML-RPC Request")
            print(f"Timestamp: {timestamp}")
            print(f"User: {user.name} (ID: {user.id})")
            print(f"Remote Address: {request.httprequest.remote_addr}")
            print(f"Method: {request.httprequest.method}")
            print(f"Content-Type: {request.httprequest.content_type}")
            print(f"Content-Length: {request.httprequest.content_length}")
            
            # Get the original request data
            request_data = request.httprequest.get_data()
            if request_data:
                print(f"Request Data Length: {len(request_data)} bytes")
                # Don't print the full data to avoid cluttering console with large payloads
                if len(request_data) < 1000:
                    print(f"Request Data: {request_data.decode('utf-8', errors='ignore')[:500]}...")
            
            print(f"{'='*60}\n")
            
            # Parse XML-RPC request to extract model and method
            parsed_request = self._parse_xmlrpc_request(request_data)
            
            if 'error' in parsed_request:
                error_msg = f"Error parsing XML-RPC request: {parsed_request['error']}"
                print(f"[MCP PROXY] ❌ {error_msg}")
                
                fault_response = self._create_xmlrpc_fault_response(100, error_msg)
                return request.make_response(
                    fault_response,
                    headers={'Content-Type': 'text/xml'},
                    status=400
                )
            
            # Extract model and method information
            model_name = parsed_request.get('model')
            odoo_method = parsed_request.get('odoo_method')
            xmlrpc_method = parsed_request.get('xmlrpc_method')
            
            print(f"[MCP PROXY] Parsed Request:")
            print(f"  XML-RPC Method: {xmlrpc_method}")
            print(f"  Target Model: {model_name}")
            print(f"  Odoo Method: {odoo_method}")
            
            # Check if we have a model to validate permissions for
            if model_name and odoo_method:
                # Map Odoo method to permission type
                permission_type = self._map_method_to_permission(odoo_method)
                print(f"  Required Permission: {permission_type}")
                
                # Check ai_mcp permissions
                permission_check = self._check_ai_mcp_permissions(user, model_name, permission_type)
                
                if not permission_check['allowed']:
                    error_msg = permission_check['message']
                    print(f"[MCP PROXY] ❌ Permission Denied: {error_msg}")
                    
                    # Return XML-RPC fault for permission denied
                    fault_response = self._create_xmlrpc_fault_response(403, error_msg)
                    return request.make_response(
                        fault_response,
                        headers={'Content-Type': 'text/xml'},
                        status=403
                    )
                
                print(f"[MCP PROXY] ✅ Permission Check Passed: {permission_check['message']}")
            else:
                print(f"[MCP PROXY] ⚠️  No model/method found for permission check, proceeding with proxy")
            
            print(f"{'='*60}\n")
            
            # Forward the request to the original XML-RPC endpoint
            original_url = f"{request.httprequest.host_url}xmlrpc/2/object"
            
            print(f"[MCP PROXY] Forwarding request to: {original_url}")
            
            # Prepare headers for forwarding
            forward_headers = {
                'Content-Type': request.httprequest.content_type or 'text/xml',
                'Content-Length': str(request.httprequest.content_length or 0),
            }
            
            # Copy authentication headers if present
            auth_header = request.httprequest.headers.get('Authorization')
            if auth_header:
                forward_headers['Authorization'] = auth_header
            
            # Make the request to the original endpoint
            response = requests.post(
                original_url,
                data=request_data,
                headers=forward_headers,
                timeout=30
            )
            
            # Log the response
            print(f"[MCP PROXY] Response received:")
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            print(f"Response Length: {len(response.content)} bytes")
            
            if response.status_code == 200:
                print(f"[MCP PROXY] ✅ Request forwarded successfully")
            else:
                print(f"[MCP PROXY] ⚠️  Non-200 status code received")
            
            print(f"{'='*60}\n")
            
            # Return the response from the original endpoint
            return request.make_response(
                response.content,
                status=response.status_code,
                headers=dict(response.headers)
            )
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Error forwarding request to XML-RPC endpoint: {str(e)}"
            print(f"[MCP PROXY] ❌ {error_msg}")
            
            # Return XML-RPC fault response
            fault_response = self._create_xmlrpc_fault_response(500, error_msg)
            return request.make_response(
                fault_response,
                headers={'Content-Type': 'text/xml'},
                status=500
            )
            
        except Exception as e:
            error_msg = f"Unexpected error in proxy: {str(e)}"
            print(f"[MCP PROXY] ❌ {error_msg}")
            
            # Return XML-RPC fault response
            fault_response = self._create_xmlrpc_fault_response(500, error_msg)
            return request.make_response(
                fault_response,
                headers={'Content-Type': 'text/xml'},
                status=500
            )

    # ------------------------------------------------------------------
    # /mcp/xmlrpc/common - XML-RPC Common Proxy Endpoint
    # ------------------------------------------------------------------
    
    @http.route("/mcp/xmlrpc/common", 
                type='http', 
                auth='none', 
                methods=['POST'], 
                csrf=False)
    def xmlrpc_common_proxy(self, **kwargs):
        """
        Proxy endpoint for XML-RPC common calls.
        
        Intercepts requests that would normally go to /xmlrpc/2/common,
        logs them, and forwards them to the original endpoint.
        
        This is a simple proxy for common XML-RPC operations like:
        - version()
        - about()
        - authenticate()
        - list_languages()
        - etc.
        """
        try:
            # Log the incoming request
            user = request.env.user
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            print(f"\n{'='*60}")
            print(f"[MCP COMMON PROXY] Incoming XML-RPC Common Request")
            print(f"Timestamp: {timestamp}")
            print(f"User: {user.name} (ID: {user.id})")
            print(f"Remote Address: {request.httprequest.remote_addr}")
            print(f"Method: {request.httprequest.method}")
            print(f"Content-Type: {request.httprequest.content_type}")
            print(f"Content-Length: {request.httprequest.content_length}")
            
            # Get the original request data
            request_data = request.httprequest.get_data()
            if request_data:
                print(f"Request Data Length: {len(request_data)} bytes")
                # Don't print the full data to avoid cluttering console with large payloads
                if len(request_data) < 1000:
                    print(f"Request Data: {request_data.decode('utf-8', errors='ignore')[:500]}...")
            
            print(f"{'='*60}\n")
            
            # Forward the request to the original XML-RPC common endpoint
            original_url = f"{request.httprequest.host_url}xmlrpc/2/common"
            
            print(f"[MCP COMMON PROXY] Forwarding request to: {original_url}")
            
            # Prepare headers for forwarding
            forward_headers = {
                'Content-Type': request.httprequest.content_type or 'text/xml',
                'Content-Length': str(request.httprequest.content_length or 0),
            }
            
            # Copy authentication headers if present
            auth_header = request.httprequest.headers.get('Authorization')
            if auth_header:
                forward_headers['Authorization'] = auth_header
            
            # Make the request to the original endpoint
            response = requests.post(
                original_url,
                data=request_data,
                headers=forward_headers,
                timeout=30
            )
            
            # Log the response
            print(f"[MCP COMMON PROXY] Response received:")
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            print(f"Response Length: {len(response.content)} bytes")
            
            if response.status_code == 200:
                print(f"[MCP COMMON PROXY] ✅ Request forwarded successfully")
            else:
                print(f"[MCP COMMON PROXY] ⚠️  Non-200 status code received")
            
            print(f"{'='*60}\n")
            
            # Return the response from the original endpoint
            return request.make_response(
                response.content,
                status=response.status_code,
                headers=dict(response.headers)
            )
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Error forwarding request to XML-RPC common endpoint: {str(e)}"
            print(f"[MCP COMMON PROXY] ❌ {error_msg}")
            
            # Return XML-RPC fault response
            fault_response = self._create_xmlrpc_fault_response(500, error_msg)
            return request.make_response(
                fault_response,
                headers={'Content-Type': 'text/xml'},
                status=500
            )
            
        except Exception as e:
            error_msg = f"Unexpected error in common proxy: {str(e)}"
            print(f"[MCP COMMON PROXY] ❌ {error_msg}")
            
            # Return XML-RPC fault response
            fault_response = self._create_xmlrpc_fault_response(500, error_msg)
            return request.make_response(
                fault_response,
                headers={'Content-Type': 'text/xml'},
                status=500
            )

    # ------------------------------------------------------------------
    # /mcp/xmlrpc/db - XML-RPC Database Proxy Endpoint
    # ------------------------------------------------------------------
    
    @http.route("/mcp/xmlrpc/db", 
                type='http', 
                auth='none', 
                methods=['POST'], 
                csrf=False)
    def xmlrpc_db_proxy(self, **kwargs):
        """
        Proxy endpoint for XML-RPC database calls.
        
        Intercepts requests that would normally go to /xmlrpc/2/db,
        logs them, and forwards them to the original endpoint.
        
        This is a simple proxy for database XML-RPC operations like:
        - list()
        - list_lang()
        - duplicate_database()
        - drop()
        - dump()
        - restore()
        - etc.
        """
        try:
            # Log the incoming request
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            print(f"\n{'='*60}")
            print(f"[MCP DB PROXY] Incoming XML-RPC Database Request")
            print(f"Timestamp: {timestamp}")
            print(f"Remote Address: {request.httprequest.remote_addr}")
            print(f"Method: {request.httprequest.method}")
            print(f"Content-Type: {request.httprequest.content_type}")
            print(f"Content-Length: {request.httprequest.content_length}")
            
            # Get the original request data
            request_data = request.httprequest.get_data()
            if request_data:
                print(f"Request Data Length: {len(request_data)} bytes")
                # Don't print the full data to avoid cluttering console with large payloads
                if len(request_data) < 1000:
                    print(f"Request Data: {request_data.decode('utf-8', errors='ignore')[:500]}...")
            
            print(f"{'='*60}\n")
            
            # Forward the request to the original XML-RPC database endpoint
            original_url = f"{request.httprequest.host_url}xmlrpc/2/db"
            
            print(f"[MCP DB PROXY] Forwarding request to: {original_url}")
            
            # Prepare headers for forwarding
            forward_headers = {
                'Content-Type': request.httprequest.content_type or 'text/xml',
                'Content-Length': str(request.httprequest.content_length or 0),
            }
            
            # Copy authentication headers if present
            auth_header = request.httprequest.headers.get('Authorization')
            if auth_header:
                forward_headers['Authorization'] = auth_header
            
            # Make the request to the original endpoint
            response = requests.post(
                original_url,
                data=request_data,
                headers=forward_headers,
                timeout=30
            )
            
            # Log the response
            print(f"[MCP DB PROXY] Response received:")
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            print(f"Response Length: {len(response.content)} bytes")
            
            if response.status_code == 200:
                print(f"[MCP DB PROXY] ✅ Request forwarded successfully")
            else:
                print(f"[MCP DB PROXY] ⚠️  Non-200 status code received")
            
            print(f"{'='*60}\n")
            
            # Return the response from the original endpoint
            return request.make_response(
                response.content,
                status=response.status_code,
                headers=dict(response.headers)
            )
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Error forwarding request to XML-RPC database endpoint: {str(e)}"
            print(f"[MCP DB PROXY] ❌ {error_msg}")
            
            # Return XML-RPC fault response
            fault_response = self._create_xmlrpc_fault_response(500, error_msg)
            return request.make_response(
                fault_response,
                headers={'Content-Type': 'text/xml'},
                status=500
            )
            
        except Exception as e:
            error_msg = f"Unexpected error in database proxy: {str(e)}"
            print(f"[MCP DB PROXY] ❌ {error_msg}")
            
            # Return XML-RPC fault response
            fault_response = self._create_xmlrpc_fault_response(500, error_msg)
            return request.make_response(
                fault_response,
                headers={'Content-Type': 'text/xml'},
                status=500
            )

