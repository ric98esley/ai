from odoo import http
from odoo.http import request
import json
import time


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
