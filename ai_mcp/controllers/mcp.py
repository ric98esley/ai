from odoo import http
from odoo.http import request
import json


class MCPController(http.Controller):
    """Controller for MCP (Model Context Protocol) endpoints."""
    
    @http.route("/mcp/models", type='http', auth='bearer', methods=['GET'], csrf=False)
    def get_models(self, **kwargs):
        """
        GET endpoint to retrieve available models.
        
        Returns:
            JSON response with list of available models and their metadata.
        """
        try:
            # Get all registered models
            models = request.env['ir.model'].sudo().search([])
            
            models_data = []
            for model in models:
                models_data.append({
                    'model': model.model,
                    'display_name': model.name,
                    'description': model.info or '',
                    'state': model.state,
                    'modules': model.modules.split(',') if model.modules else [],
                    'fields_count': len(model.field_id),
                })
            
            return json.dumps({
                'status': 'success',
                'data': {
                    'models': models_data,
                    'total_count': len(models_data)
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
        GET endpoint to check access permissions for a specific model.
        
        Args:
            model (str): The model name to check access for.
            
        Returns:
            JSON response with access permissions information.
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
            
            # Check access rights
            access_rights = request.env['ir.model.access'].sudo().search([
                ('model_id', '=', model_record.id),
                ('group_id', 'in', user.groups_id.ids)
            ])
            
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
                'groups': [group.name for group in user.groups_id]
            }
            
            # Check permissions from access rights
            for access in access_rights:
                access_info['permissions']['read'] = access_info['permissions']['read'] or access.perm_read
                access_info['permissions']['write'] = access_info['permissions']['write'] or access.perm_write
                access_info['permissions']['create'] = access_info['permissions']['create'] or access.perm_create
                access_info['permissions']['delete'] = access_info['permissions']['delete'] or access.perm_unlink
                access_info['permissions']['unlink'] = access_info['permissions']['unlink'] or access.perm_unlink
            
            # Check if user is admin (superuser)
            if user.has_group('base.group_system'):
                access_info['permissions'] = {
                    'read': True,
                    'write': True,
                    'create': True,
                    'delete': True,
                    'unlink': True
                }
                access_info['is_admin'] = True
            
            return json.dumps({
                'status': 'success',
                'data': access_info
            }, indent=2)
            
        except Exception as e:
            return json.dumps({
                'status': 'error',
                'message': str(e)
            }, indent=2), 500


