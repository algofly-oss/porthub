async function chooseDropdown(input,label){
 await input.click();await input.fill(String(label));
 await input.page().getByRole('option',{name:String(label),exact:true}).click();
}
module.exports={chooseDropdown};
