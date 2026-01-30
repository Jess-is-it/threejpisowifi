/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{html,js}", "./node_modules/flowbite/**/*.js"],
  theme: {
    extend: {
      colors: {
        ink: "#0b1220",
      },
    },
  },
  plugins: [require("flowbite/plugin")],
};

