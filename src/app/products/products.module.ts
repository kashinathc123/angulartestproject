import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ProductsRoutingModule} from './products-routing.module'; //Added
import { ProductService } from './productService';
import { FormsModule } from '@angular/forms';
import { SharedModule } from '../shared/shared.module';
import { ProductListComponent } from './product-list/product-list.component';
import { ProductsComponent } from './products.component';
import { ProductDetailComponent } from './product-detail/product-detail.component';
import { RegisterComponent } from './register/register.component';
import { ProfileFormComponent } from './common-form/common-form.component';
import { ProductEditComponent } from './product-edit/product-edit.component';
import { CartComponent } from './cartComponent/cartComponent';
import { CartService } from './cartComponent/cartComponent.service';

@NgModule({
  imports: [    
    CommonModule,
    SharedModule,
    FormsModule,
    ProductsRoutingModule  // Added
  ],
  providers: [ProductService],
  declarations: [ ProductsComponent, 
    ProductListComponent, 
    ProductDetailComponent,
    RegisterComponent,
    ProfileFormComponent,
    ProductEditComponent,
    CartComponent
  ]
})
export class ProductsModule { }
