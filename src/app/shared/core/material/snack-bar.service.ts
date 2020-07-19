import { Injectable } from '@angular/core';
import { Observable, Subject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class SnackBarService {
  durationInSeconds$ = 3;
  snackBarMethod$: Observable<any>;
  private snackBarMethodSubject = new Subject<any>();
  constructor() {
    this.snackBarMethod$ = this.snackBarMethodSubject.asObservable();
   }

   getsnackbarData(data) {
   // console.log(data); // I have data! Let's return it so subscribers can use it!
    // we can do stuff with data if we want
    this.snackBarMethodSubject.next(data);
   // console.log(data); 
}
}
