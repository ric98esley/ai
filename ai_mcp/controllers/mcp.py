from odoo import http
from odoo.http import request
import json


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
                        'display_name': model.name
                    })
            
            return json.dumps({
                'status': 'success',
                'data': {
                    'models': models_data,
                    'total_count': len(models_data),
                }
            }, indent=2)
            
        except Exception as e:
            return json.dumps({
                'status': 'error',
                'message': str(e)
            }, indent=2), 500
    
    @http.route("/mcp/user/permissions", type='http', auth='bearer', methods=['GET'], csrf=False)
    def get_user_permissions(self, **kwargs):
        """
        GET endpoint to retrieve all permissions for the current user.
        
        Returns:
            JSON response with all user permissions from ai_mcp system.
        """
        try:
            # Get current user
            user = request.env.user
            
            # Get all user permissions from ai_mcp system
            user_permissions = request.env['ai_mcp.model_permission'].sudo().search([
                ('user_id', '=', user.id),
                ('active', '=', True)
            ])
            
            permissions_data = []
            for permission in user_permissions:
                model = permission.model_id
                if model:
                    permissions_data.append({
                        'permission_id': permission.id,
                        'model': model.model,
                        'model_name': model.name,
                        'model_display_name': model.name,
                        'permissions': {
                            'read': permission.perm_read,
                            'write': permission.perm_write,
                            'create': permission.perm_create,
                            'delete': permission.perm_unlink,
                            'unlink': permission.perm_unlink
                        },
                        'permission_summary': permission.permission_summary,
                        'notes': permission.notes or '',
                        'active': permission.active
                    })
            
            return json.dumps({
                'status': 'success',
                'data': {
                    'user_id': user.id,
                    'user_name': user.name,
                    'permissions': permissions_data,
                    'total_permissions': len(permissions_data)
                }
            }, indent=2)
            
        except Exception as e:
            return json.dumps({
                'status': 'error',
                'message': str(e)
            }, indent=2), 500
    
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
                }, indent=2), 404
            
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
                'model_name': model_record.name,
                'user_id': user.id,
                'user_name': user.name,
                'permissions': {
                    'read': False,
                    'write': False,
                    'create': False,
                    'delete': False,
                    'unlink': False
                },
                'has_ai_mcp_permission': False,
                'permission_summary': 'No permissions'
            }
            
            # If user has ai_mcp permission for this model
            if permission:
                access_info['permissions'] = {
                    'read': permission.perm_read,
                    'write': permission.perm_write,
                    'create': permission.perm_create,
                    'delete': permission.perm_unlink,
                    'unlink': permission.perm_unlink
                }
                access_info['has_ai_mcp_permission'] = True
                access_info['permission_summary'] = permission.permission_summary
                access_info['permission_id'] = permission.id
                access_info['notes'] = permission.notes or ''
            
            # Check if user is admin (superuser) - admins get full access regardless of ai_mcp permissions
            if user.has_group('base.group_system'):
                access_info['permissions'] = {
                    'read': True,
                    'write': True,
                    'create': True,
                    'delete': True,
                    'unlink': True
                }
                access_info['is_admin'] = True
                access_info['permission_summary'] = 'Full admin access'
            
            return json.dumps({
                'status': 'success',
                'data': access_info
            }, indent=2)
            
        except Exception as e:
            return json.dumps({
                'status': 'error',
                'message': str(e)
            }, indent=2), 500


