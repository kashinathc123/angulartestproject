import { Component, OnInit, AfterViewInit, AfterViewChecked, ViewChild, ChangeDetectorRef, ViewChildren, QueryList } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { ProductService } from '../productService';
import { FormBuilder, FormGroup, FormControl } from '@angular/forms';
import { ProfileFormComponent } from '../common-form/common-form.component';
import { MatSnackBar } from '@angular/material/snack-bar';
import { SnackBarComponent } from 'src/app/shared/core/material/snack-bar/snack-bar.component';
import { SnackBarService } from 'src/app/shared/core/material/snack-bar.service';

@Component({
  selector: 'app-product-edit',
  templateUrl: './product-edit.component.html',
  styleUrls: ['./product-edit.component.css']
})
export class ProductEditComponent implements OnInit, AfterViewChecked , AfterViewInit {
  pageTitle="Edit product";
  public _check: boolean;
  public _checkStatus: boolean;
  productList;
  product;
  productId;
  editProductForm: FormGroup;
  profile: FormControl;

  @ViewChildren(ProfileFormComponent) myName: QueryList<ProfileFormComponent>;
  @ViewChild(ProfileFormComponent,{static:true}) myValue: ProfileFormComponent; 

  set check (value){
    this._check = value;
  }
 
  get check (){
     return this._check;
  }

  set checkVal (val){
    this._checkStatus = val;
  }
 
  get checkVal (){
     return this._checkStatus;
  }

  constructor(private formBuilder: FormBuilder, private route: ActivatedRoute, 
    private router: Router,
    private cdr : ChangeDetectorRef,
    private productService: ProductService,
    private _snackBar: MatSnackBar,private snackbarService: SnackBarService) {
    this.editProductForm = this.formBuilder.group({
      profile: []
    });
   }

  ngOnInit() {
    this._check = false;
    this.route.params.subscribe(params => {
      let id = params["id"];
      this.productService
        .get_products()        
        .subscribe(res => {
          this.productList = res;
          this.getProduct(id);
        });
    });
    if (this.editProductForm === this.editProductForm.value) {
      console.log('changes are there');
    } else {
      console.log('no changes are there');
    }   
  }

  getProduct(id) {
    this.product = this.productList.filter(x => x.id == id)[0];
    console.log(this.product);
    this.productId = this.product.id;
    this.onLoadData();   
  }

  onLoadData() {
    console.log('Hi',this.productId);
   // this.profile.setPatchValue(this.product);
   this.editProductForm.controls.profile.patchValue(
     {
      productId: this.product.id,
      productName: this.product.productName,
      price: this.product.price,
      color: this.product.color,
      quantity: this.product.quantity,
      size: this.product.size,
      category: this.product.category
     }
   );
   // console.log(this.editProductForm.controls.profile.color);
  }

  updateProductForm(values){  
    const productData = values.profile;    
    console.log(productData);     
    this.productService.UpdateProductData(productData).subscribe(result => {
      this.router.navigate(['/products']);
      console.log('result',result);
      const snackbarItem = productData.productName;
      this.snackbarService.getsnackbarData(snackbarItem);
    });
    this.openSnackBar();    
  }

  ngAfterViewChecked() {
    this._check = this.myName.first.profileForm.dirty;
    this._checkStatus = this.myValue.profileForm.invalid;
    console.log('ViewChildren',this._check);
    console.log('ViewChild',this._checkStatus);
    this.cdr.detectChanges();
}

ngAfterViewInit() {
     console.log('viewinit', this.myName.first.profileForm.dirty);
}

resetForm() {
 this.editProductForm.reset();
 this.onLoadData();
 //this._check = false;
}

openSnackBar() {
  this._snackBar.openFromComponent(SnackBarComponent, {
    duration: this.snackbarService.durationInSeconds$ * 1000,
  });
}

}
