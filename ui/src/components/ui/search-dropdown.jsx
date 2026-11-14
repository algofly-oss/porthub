import {Children,isValidElement} from 'react';
import SearchSelect from './search-select';

// Accept option children while rendering the same searchable control used by
// inventory pickers. Existing form values and change handlers stay compatible.
function text(node){return Children.toArray(node).map(child=>isValidElement(child)?text(child.props.children):String(child)).join('');}
export default function SearchDropdown({children,value,onChange,className='',required=false,...props}){
 const items=Children.toArray(children).filter(isValidElement).map(option=>({value:String(option.props.value??text(option.props.children)),label:text(option.props.children),disabled:!!option.props.disabled}));
 const placeholder=items.find(item=>item.value==='')?.label;
 const layout=className.split(/\s+/).filter(token=>/^(?:(?:sm|md|lg|xl):)?(?:w-|min-w-|max-w-|flex-|grow|shrink|mt-|mb-|self-|col-)/.test(token)).join(' ');
 return <SearchSelect {...props} aria-required={required||undefined} label={props['aria-label']} className={`min-w-0 ${layout}`} value={value==null?'':String(value)} placeholder={placeholder} options={items.filter(item=>item.value!=='')} onChange={next=>onChange?.({target:{value:next},currentTarget:{value:next}})}/>;
}
