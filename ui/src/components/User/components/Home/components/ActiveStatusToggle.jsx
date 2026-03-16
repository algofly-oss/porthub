export default function ActiveStatusToggle({ value, onClick }) {
  return (
    <div className="pt-1 rounded-lg">
      <label
        htmlFor="checked-toggle"
        className="inline-flex relative items-center cursor-pointer"
        onClick={onClick}
      >
        <input
          type="checkbox"
          className="sr-only peer"
          checked={value}
          onChange={(e) => {}}
        />
        <div className="w-11 h-6 bg-gray-200 rounded-full dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-cyan-500" />
      </label>
    </div>
  );
}
