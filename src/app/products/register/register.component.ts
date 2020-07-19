import { Component, OnInit, ChangeDetectionStrategy } from '@angular/core';
import { NgForm, FormGroup, FormBuilder, Validators } from '@angular/forms';
import { ProductService } from '../productService';
import { Router } from '@angular/router';
import {MatDialog} from '@angular/material/dialog';
import { DialogComponent } from 'src/app/shared/core/material/dialog/dialog.component';
import { MatSnackBar } from '@angular/material/snack-bar';
import { SnackBarComponent } from 'src/app/shared/core/material/snack-bar/snack-bar.component';
import { SnackBarService } from 'src/app/shared/core/material/snack-bar.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.scss']
})
export class RegisterComponent {
  pageTitle = "Add new product";
signupForm: FormGroup;
productValues;
// durationInSeconds = 15;

constructor(private formBuilder: FormBuilder, private productService: ProductService, private router: Router,
 private _snackBar: MatSnackBar,
 private snackbarService: SnackBarService) {
  this.signupForm = this.formBuilder.group({
    profile: [],
    rating:[]
  });
}

// openDialog() {
//   const dialogRef = this.dialog.open(DialogComponent);

//   dialogRef.afterClosed().subscribe(result => {
//     console.log(`Dialog result: ${result}`);
//   });
// }

openSnackBar() {
  this._snackBar.openFromComponent(SnackBarComponent, {
    duration: this.snackbarService.durationInSeconds$ * 1000,
  });
}

submit() {
  console.log(this.signupForm.value);  
}

saveProduct(values){  
  const productData = values.profile;
  console.log(productData.productName); 
  this.productService.createProduct(productData).subscribe(result => {
    this.router.navigate(['/products']);
    console.log('result',result);
    const snackbarItem = productData.productName;
    this.snackbarService.getsnackbarData(snackbarItem);
  });
  //this.openDialog();
  this.openSnackBar();
  //this.snackbarService.myMethod(compo);
//   this.cartservice.myMethod$.subscribe((data) => {
//     this.cartvalueLength = data.length; // And he have data here too!
//     console.log('this.itemLength',this.itemLength);
// }
}

resetForm() {
  this.signupForm.reset();
}

}
