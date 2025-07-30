from odoo import models, fields, api


class ModelPermission(models.Model):
    """Model to manage user-specific model permissions for MCP."""
    _name = 'ai_mcp.model_permission'
    _description = 'Model Permission'
    _rec_name = 'model_name'
    _order = 'user_id, model_name'
    
    # User relationship
    user_id = fields.Many2one(
        'res.users', 
        string='User', 
        required=True, 
        ondelete='cascade',
        help='User who will have these permissions'
    )
    
    # Model selection
    model_id = fields.Many2one(
        'ir.model', 
        string='Model', 
        required=True, 
        ondelete='cascade',
        help='Odoo model to grant permissions for'
    )
    
    model_name = fields.Char(
        related='model_id.model', 
        string='Model Name', 
        store=True,
        help='Technical name of the model'
    )
    
    model_display_name = fields.Char(
        related='model_id.name', 
        string='Model Display Name', 
        store=True,
        help='Human readable name of the model'
    )
    
    # Permission fields
    perm_read = fields.Boolean(
        string='Read', 
        default=True,
        help='Allow user to read records from this model'
    )
    
    perm_write = fields.Boolean(
        string='Write', 
        default=False,
        help='Allow user to modify records in this model'
    )
    
    perm_create = fields.Boolean(
        string='Create', 
        default=False,
        help='Allow user to create new records in this model'
    )
    
    perm_unlink = fields.Boolean(
        string='Delete', 
        default=False,
        help='Allow user to delete records from this model'
    )
    
    # Additional fields
    active = fields.Boolean(
        string='Active', 
        default=True,
        help='Enable or disable this permission set'
    )
    
    notes = fields.Text(
        string='Notes',
        help='Additional notes about this permission set'
    )
    
    # Computed fields
    permission_summary = fields.Char(
        string='Permissions', 
        compute='_compute_permission_summary',
        store=True,
        help='Summary of granted permissions'
    )
    
    @api.depends('perm_read', 'perm_write', 'perm_create', 'perm_unlink')
    def _compute_permission_summary(self):
        """Compute a human-readable summary of permissions."""
        for record in self:
            permissions = []
            if record.perm_read:
                permissions.append('Read')
            if record.perm_write:
                permissions.append('Write')
            if record.perm_create:
                permissions.append('Create')
            if record.perm_unlink:
                permissions.append('Delete')
            
            if permissions:
                record.permission_summary = ', '.join(permissions)
            else:
                record.permission_summary = 'No permissions'
    
    @api.constrains('user_id', 'model_id')
    def _check_unique_user_model(self):
        """Ensure each user can only have one permission set per model."""
        for record in self:
            existing = self.search([
                ('user_id', '=', record.user_id.id),
                ('model_id', '=', record.model_id.id),
                ('id', '!=', record.id)
            ])
            if existing:
                raise models.ValidationError(
                    f'User {record.user_id.name} already has permissions for model {record.model_id.name}'
                )
    
    @api.onchange('model_id')
    def _onchange_model_id(self):
        """Update related fields when model changes."""
        if self.model_id:
            self.model_name = self.model_id.model
            self.model_display_name = self.model_id.name
    
    def name_get(self):
        """Custom name display for the record."""
        result = []
        for record in self:
            name = f"{record.user_id.name} - {record.model_display_name}"
            if record.permission_summary:
                name += f" ({record.permission_summary})"
            result.append((record.id, name))
        return result
    
    def get_user_permissions(self, user_id, model_name):
        """Get permissions for a specific user and model."""
        permission = self.search([
            ('user_id', '=', user_id),
            ('model_name', '=', model_name),
            ('active', '=', True)
        ], limit=1)
        
        if permission:
            return {
                'read': permission.perm_read,
                'write': permission.perm_write,
                'create': permission.perm_create,
                'unlink': permission.perm_unlink,
            }
        return {
            'read': False,
            'write': False,
            'create': False,
            'unlink': False,
        }
