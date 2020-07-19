import { Component, OnInit } from '@angular/core';
import { SnackBarService } from '../snack-bar.service';

@Component({
  selector: 'app-snack-bar',
  templateUrl: './snack-bar.component.html',
  styleUrls: ['./snack-bar.component.css']
})
export class SnackBarComponent implements OnInit {
  snackbarItemName;
  constructor(private snackbarService: SnackBarService) { 
    this.snackbarService.snackBarMethod$.subscribe((data) => {
      this.snackbarItemName = data; // And he have data here too!
     // console.log('this.snackbarItemName',this.snackbarItemName);
    });
  }

  ngOnInit() {
   // this.snackbarService.myMethod(compo);
  }

  


}
