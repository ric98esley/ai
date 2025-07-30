# from odoo import models, fields, api


# class ai_mcp(models.Model):
#     _name = 'ai_mcp.ai_mcp'
#     _description = 'ai_mcp.ai_mcp'

#     name = fields.Char()
#     value = fields.Integer()
#     value2 = fields.Float(compute="_value_pc", store=True)
#     description = fields.Text()
#
#     @api.depends('value')
#     def _value_pc(self):
#         for record in self:
#             record.value2 = float(record.value) / 100
