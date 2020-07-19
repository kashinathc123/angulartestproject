import { Pipe, PipeTransform, } from "@angular/core";

@Pipe({
    name:'startsWith'
})
export class smartSearch implements PipeTransform{
    transform(value: any, args?: any): any {
        if (!args) {
          return value;
        }
        return value.filter((val) => {
          let rVal = (
            val.productName.toLocaleLowerCase().includes(args) ||
            val.size.toLocaleLowerCase().includes(args) ||
            val.category.toLocaleLowerCase().includes(args) ||
            val.quantity.toLocaleLowerCase().includes(args) ||
            val.color.toLocaleLowerCase().includes(args) ||
            val.price.toLocaleLowerCase().includes(args)
          );
          return rVal;
        })
    
      }
}