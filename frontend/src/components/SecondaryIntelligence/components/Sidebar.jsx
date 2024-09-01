import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useAuthContext } from "../../../hooks/useAuthContext";
import { darkColors, lightColors } from "../data/sidebarTheme";

function useOnMount(callback) {
  useEffect(callback, []); // Empty dependency array ensures it only runs once
}

const SideBar = ({ lightMode }) => {
  const [dishHistory, setDishHistory] = useState([]);
  const [error, setError] = useState(null);
  const { user } = useAuthContext();
  const colors = lightMode ? lightColors : darkColors;

  // useEffect(() => {
  //   const fetchDishHistory = async () => {
  //     try {
  //       const response = await fetch("http://localhost:5000/api/dish_history");
  //       if (response.ok) {
  //         const data = await response.json();
  //         setDishHistory(data.dishes);
  //       } else {
  //         console.error("Failed to fetch dish history");
  //       }
  //     } catch (error) {
  //       console.error("Error fetching dish history:", error);
  //     }
  //   };

  //   if (user) {
  //     fetchDishHistory();
  //   }
  // }, []);

  useOnMount(() => {
    const fetchDishHistory = async () => {
      try {
        const response = await fetch("http://localhost:5000/api/dish_history");
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        if (data.error) {
          throw new Error(data.error);
        }
        setDishHistory(data.dishes);
      } catch (error) {
        console.error("Error fetching dish history:", error.message);
        setError(error.message);
      }
    };

    fetchDishHistory();
  });

  if (error) {
    return <div>Error: {error}</div>;
  }

  return (
    <div
      className={`fixed top-[56px] left-0 lg:relative flex flex-col lg:w-1/5 h-[calc(100dvh-56px)] lg:h-auto lg:top-0 overflow-y-auto ${colors.background} ${colors.text} text-white shadow-2xl`}
    >
      {!user ? (
        <div className="w-[250px] md:w-full h-[100%] flex items-center justify-center">
          <Link
            to="/login"
            className="w-fit bg-orange-600 px-4 py-2 rounded-md text-lg"
          >
            Login
          </Link>
        </div>
      ) : (
        <>
          <div className="p-4">
            <h2 className="text-xl font-bold mb-4">Dish History</h2>
            <ul className="space-y-2">
              {dishHistory.map((dish, index) => (
                <li
                  key={index}
                  className="cursor-pointer hover:bg-gray-700 p-2 rounded"
                >
                  <div className="flex items-center">
                    <span>{dish.name}</span>
                  </div>
                  <div className="text-sm text-gray-400">{dish.date}</div>
                </li>
              ))}
            </ul>
          </div>
          <div className="mt-auto p-4">
            <button className="w-full bg-orange-600 px-4 py-2 rounded-md text-lg">
              New Dish
            </button>
          </div>
        </>
      )}
    </div>
  );
};

export default SideBar;
