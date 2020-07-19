import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { ProductsComponent } from './products.component';
import { ProductListComponent } from './product-list/product-list.component';
import { ProductDetailComponent } from './product-detail/product-detail.component';
import { PageNotFoundComponent } from '../shared/page-not-found/page-not-found.component';
import { RegisterComponent } from './register/register.component';
import { ProductEditComponent } from './product-edit/product-edit.component';
import { CartComponent } from './cartComponent/cartComponent';

const productRoutes: Routes = [
  {
    path: '', 
    component: ProductsComponent,
    children: [
      { path: ':id/detail', component: ProductDetailComponent },   
      { path: 'add-new-product', component: RegisterComponent },
      { path: ':id/edit', component: ProductEditComponent },
      { path:'cart', component: CartComponent},  
      { path:'', component: ProductListComponent  },
      { path: '**', component: PageNotFoundComponent }
    ]
  }
]

@NgModule({
  imports: [    
    RouterModule.forChild(productRoutes)
  ],
  exports:[RouterModule]
})
export class ProductsRoutingModule { }
