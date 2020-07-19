import {
  Component,
  forwardRef,
  OnDestroy,
  ChangeDetectionStrategy,
  OnInit,
  ViewChild
} from "@angular/core";
import {
  ControlValueAccessor,
  NG_VALUE_ACCESSOR,
  FormBuilder,
  FormGroup,
  Validators,
  FormControl,
  NG_VALIDATORS
} from "@angular/forms";
import { Subscription } from "rxjs";

export interface ProfileFormValues {
  productId: number;
  productName: string;
  email: number;
  price: number;
  color: string[];
  quantity: number;
  size: string[];
  categorylist: string[];
}

@Component({
  selector: "app-common-form",
  templateUrl: "./common-form.component.html",
  styleUrls: ["./common-form.component.css"],
  providers: [
    {
      provide: NG_VALUE_ACCESSOR,
      useExisting: forwardRef(() => ProfileFormComponent),
      multi: true
    },
    {
      provide: NG_VALIDATORS,
      useExisting: forwardRef(() => ProfileFormComponent),
      multi: true
    }
  ]
})
export class ProfileFormComponent
  implements ControlValueAccessor, OnInit, OnDestroy {
  profileForm: FormGroup;
  subscriptions: Subscription[] = [];
  categorylist;
  size;
  color;
  external: string;
  
  get value(): ProfileFormValues {
    return this.profileForm.value;
  }

  set value(value: ProfileFormValues) {
    this.profileForm.setValue(value);
    this.onChange(value);
    this.onTouched();
  }

  get emailControl() {
    return this.profileForm.controls.email;
  }

  constructor(private formBuilder: FormBuilder) {
    this.profileForm = this.formBuilder.group({
      productId: [""],
      productName: [
        "",
        [Validators.required, Validators.pattern("^[a-zA-Z ]*$")]
      ],
      price: [
        "",
        [
          Validators.required,
          Validators.pattern("^[0-9]*$"),
          Validators.maxLength(9)
        ]
      ],
      color: ["", [Validators.required]],
      quantity: [
        "",
        [
          Validators.required,
          Validators.pattern("^[0-9]*$"),
          Validators.maxLength(2)
        ]
      ],
      size: ["", [Validators.required]],
      category: ["", [Validators.required]]
    });

    this.subscriptions.push(
      this.profileForm.valueChanges.subscribe(value => {
        this.onChange(value);
        this.onTouched();
      })
    );
  }
  ngOnInit() {
    this.categorylist = [
      "Clothing & Shoes",
      "Computers",
      "Automotive",
      "Baby & Toddler",
      "Gifts",
      "Automobile",
      "Food",
      "Electronics",
      "Mobile",
      "Furniture",
      "Crockery"
    ];
    this.size = ["Small", "Medium", "Large", "XL", "XXL", "XXXL"];
    this.color = ["Black", "Red", "Green", "Blue", "Pink", "Yellow"];
  }

  get f() {
    return this.profileForm.controls;
  }

  public getErrorMessage() {
    if(this.profileForm.controls.productName.hasError('required') == true){
      return 'You must enter product name';
    }else if(this.profileForm.controls.productName.hasError('pattern') == true){
           return 'Not a valid product name';
    }

    if(this.profileForm.controls.price.hasError('required') == true){
      return 'You must enter price';
    }else if(this.profileForm.controls.price.hasError('pattern') == true){
           return 'Not a valid price';
    }
  //  if( this.profileForm.controls.productName.hasError == 'required'){
  //      return 'You must enter product name';
  //    }else if(this.profileForm.controls.productName.hasError == 'pattern'){
  //      return 'Not a valid product name';
  //    }
   // this.profileForm.controls.productName.hasError('required') ? 'You must enter product name' : this.profileForm.controls.productName.hasError('pattern') ? 'Not a valid product name' :
   // '' ||
  // this.profileForm.controls.price.hasError('required') ? 'You must enter price' : this.profileForm.controls.price.hasError('pattern') ? 'Not a valid price' :
  //  this.profileForm.controls.price.hasError('maxLength') ? 'Not a valid maxlength' : ''; }
    
  }
  

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }
  val = "Kashinath";
  onChange: any = () => {};
  onTouched: any = () => {};

  registerOnChange(fn) {
    this.onChange = fn;
  }

  writeValue(val) {
    if (val) {
      this.value = val;
    }

    if (val === null) {
      this.profileForm.reset();
    }
  }

  registerOnTouched(fn) {
    this.onTouched = fn;
  }

  validate(_: FormControl) {
    return this.profileForm.valid ? null : { profile: { valid: false } };
  }
}
