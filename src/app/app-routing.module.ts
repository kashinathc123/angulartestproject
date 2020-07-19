import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { HomeComponent } from './home/home.component';
import { PageNotFoundComponent } from './shared/page-not-found/page-not-found.component';
import { HomeChildComponent } from './home/home-child/home-child.component';

const routes: Routes = [
  {
    path: 'customers',
    loadChildren: '../app/customers/customer.module#CustomersModule'
  },
  {
    path:'products',
    loadChildren: '../app/products/products.module#ProductsModule'
  },
  {
    path: 'home',
    component: HomeComponent
  },
  {
    path: '',
    redirectTo: 'products',
    pathMatch: 'full'
  },
  {
    path: '**',
    component: PageNotFoundComponent
  } 
];

@NgModule({
  imports: [
    RouterModule.forRoot(routes)
  ],
  exports: [RouterModule],
  declarations:[HomeComponent, HomeChildComponent],
  providers: []
})
export class AppRoutingModule { }
