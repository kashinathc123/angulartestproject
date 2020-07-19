import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormsModule }     from '@angular/forms';
import { HeaderComponent } from './header/header.component';
import { RouterModule } from '@angular/router';
import { smartSearch } from './pipes/customSearch.pipe';
import { PageNotFoundComponent } from './page-not-found/page-not-found.component';
import { RatingComponent } from './core/rating/rating.component';
import { MaterialModule } from './core/material/material.module';

@NgModule({
  declarations: [HeaderComponent, smartSearch,
    RatingComponent, 
    PageNotFoundComponent,
    ],
  imports: [
    CommonModule,
    FormsModule,
    RouterModule,
    MaterialModule
  ],
  providers: [ ],
  exports: [
    HeaderComponent,
    smartSearch,
    PageNotFoundComponent,
    RatingComponent,
    ReactiveFormsModule,
    MaterialModule
  ]
})
export class SharedModule { }
