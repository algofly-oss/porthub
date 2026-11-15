import styles from './Settings.module.css';

export default function SettingSwitch({ label, hint, checked, onChange, disabled = false, ariaLabel }) {
  return <label className={styles.row} data-disabled={disabled || undefined}>
    <span className={styles.text}><span className={styles.title}>{label}</span>{hint && <span className={styles.hint}>{hint}</span>}</span>
    <span className={styles.switch}><input type="checkbox" role="switch" aria-label={ariaLabel || label} checked={checked} disabled={disabled} onChange={onChange}/><span className={styles.track} aria-hidden="true"/><span className={styles.thumb} aria-hidden="true"/></span>
  </label>;
}
