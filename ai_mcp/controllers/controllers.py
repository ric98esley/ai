# from odoo import http


# class AiMcp(http.Controller):
#     @http.route('/ai_mcp/ai_mcp', auth='public')
#     def index(self, **kw):
#         return "Hello, world"

#     @http.route('/ai_mcp/ai_mcp/objects', auth='public')
#     def list(self, **kw):
#         return http.request.render('ai_mcp.listing', {
#             'root': '/ai_mcp/ai_mcp',
#             'objects': http.request.env['ai_mcp.ai_mcp'].search([]),
#         })

#     @http.route('/ai_mcp/ai_mcp/objects/<model("ai_mcp.ai_mcp"):obj>', auth='public')
#     def object(self, obj, **kw):
#         return http.request.render('ai_mcp.object', {
#             'object': obj
#         })
