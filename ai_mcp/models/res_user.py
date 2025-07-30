from odoo import models, fields, api


class ResUser(models.Model):
    _inherit = 'res.users'

    ai_mcp_model_permissions = fields.One2many(
        'ai_mcp.model_permission',
        'user_id',
        string='Ai MCP Model Permissions'
    )
