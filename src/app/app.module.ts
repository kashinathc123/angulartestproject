import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { AppRoutingModule } from './app-routing.module';


import { AppComponent } from './app.component';
import { HttpClientModule } from '@angular/common/http';
import { SharedModule } from './shared/shared.module';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { DialogComponent } from './shared/core/material/dialog/dialog.component';
import { MatDialogModule } from '@angular/material/dialog';
import { SnackBarComponent } from './shared/core/material/snack-bar/snack-bar.component';
import { CartService } from './products/cartComponent/cartComponent.service';
// import {MatAutocompleteModule,MatInputModule} from '@angular/material'



@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    BrowserModule,
    FormsModule,
    SharedModule,    
    AppRoutingModule,
    HttpClientModule,
    ReactiveFormsModule,
    MatDialogModule,
    BrowserAnimationsModule,    
  ],
  providers: [CartService],
  bootstrap: [AppComponent],
  entryComponents:[DialogComponent,SnackBarComponent],
  exports:[MatDialogModule]
})
export class AppModule { }