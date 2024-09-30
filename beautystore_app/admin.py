from django.contrib import admin
from .models import  Customer, PurchaseOrder, PurchaseOrderItem, Seller, Category, Subcategory, Product, Order, OrderItem
from django.utils.html import format_html
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings


@admin.register(Seller)
class SellerAdmin(admin.ModelAdmin):
    list_display = ['name', 'email', 'phone_no', 'address']
    search_fields = ['name', 'email', 'phone_no']

class SubcategoryInline(admin.TabularInline):
    model = Subcategory
    extra = 1

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    inlines = [SubcategoryInline]

    def get_subcategory_count(self, obj):
        return obj.subcategory_set.count()

    get_subcategory_count.short_description = 'Subcategory Count'

    list_display = ['category_name', 'get_subcategory_count']
    search_fields = ['category_name']


@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    pass


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ['id', 'customer_name', 'email', 'contact_number']
    search_fields = ['customer_name', 'email', 'contact_number']
    

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['display_image','name', 'seller', 'subcategory', 'price', 'quantity_in_stock']
    list_filter = ['seller','subcategory']
    search_fields = ['name']
    def display_image(self, obj):
        return format_html('<img src="{}" width="50px" height="50px" />', obj.image.url)  # Changed obj.image_1 to obj.image

    display_image.short_description = 'Image'
    
    def changelist_view(self, request, extra_context=None):
        # Check stock levels for each product
        for product in Product.objects.all():
            if product.quantity_in_stock < product.reorder_level:
                messages.warning(request, f"Low stock alert: {product.name}")

        # Call the superclass changelist_view to render the page
        return super().changelist_view(request, extra_context=extra_context)

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ['id', 'customer', 'address', 'order_date', 'status']
    list_filter = ['status']
    search_fields = ['customer__customer_name']
    
    

class InventoryProduct(Product):
    class Meta:
        proxy = True
        verbose_name = 'Inventory'
        verbose_name_plural = 'Inventory'

class InventoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'quantity_in_stock', 'reorder_level']
    list_filter = ['seller','subcategory']
    fields = ('quantity_in_stock', 'reorder_level')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def get_readonly_fields(self, request, obj=None):
        return [f.name for f in obj._meta.fields if f.name not in ['quantity_in_stock', 'reorder_level']]
    
    def changelist_view(self, request, extra_context=None):
        # Check stock levels for each product
        for product in InventoryProduct.objects.all():
            if product.quantity_in_stock < product.reorder_level:
                messages.warning(request, f"Low stock alert: {product.name}")
                
                # Send email to admin
                send_mail(
                    'Low stock alert',
                    f'The product "{product.name}" is low on stock.',
                    settings.EMAIL_HOST_USER,  # Replace with your email
                    ['saluanngeorge@gmail.com'],  # Replace with admin email
                    fail_silently=False,
                )

        # Call the superclass changelist_view to render the page
        return super().changelist_view(request, extra_context=extra_context)

admin.site.register(InventoryProduct, InventoryAdmin)

class PurchaseOrderItemInline(admin.TabularInline):
    model = PurchaseOrderItem
    extra = 1
    readonly_fields = ['Quantity', 'Product', 'PurchaseUnitPrice', 'TotalAmount']

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

class PurchaseOrderAdmin(admin.ModelAdmin):
    def purchase_order_display(self, obj):
        return f"{obj.id} -{obj.PurchaseOrderDate}"
    purchase_order_display.short_description = 'Purchase Order'

    list_display = ['purchase_order_display', 'TotalAmount', 'PurchaseOrderDate', 'Status', 'ExpectedDeliveryDate', 'Seller']
    inlines = [PurchaseOrderItemInline]
    readonly_fields = [f.name for f in PurchaseOrder._meta.fields]

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.exclude(Status='Not Initiated')

    def has_add_permission(self, request):
        return False


admin.site.register(PurchaseOrder, PurchaseOrderAdmin)