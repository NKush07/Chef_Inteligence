import React from "react";
import { FaCopy } from "react-icons/fa";
import { toast } from "react-hot-toast";

export default function RecipeDetails({ recipe, lightMode }) {
  if (!recipe) {
    return <div>Loading...</div>;
  }

  const { name, video, ingredients, steps } = recipe;

  const handleCopy = () => {
    navigator.clipboard.writeText(
      `Dish:${name}\nIngredients:-\n${ingredients.join(
        "\n"
      )}\nSteps:-\n${steps.join("\n")}`
    );
    toast.success("Copied to clipboard!");
  };

  return (
    <div className="bg-cream-100 rounded-lg shadow-xl p-4 max-w-3xl mx-auto">
      <h1 className="text-3xl font-bold text-center mb-6">{name}</h1>

      <h2 className="text-xl font-semibold mb-4">Preparation Steps</h2>

      <div className="flex justify-end mt-4">
        <button className="bg-gray-100 rounded p-2" onClick={handleCopy}>
          <FaCopy className="text-2xl text-gray-400" />
        </button>
      </div>

      <ol className="list-decimal pl-6 mb-6">
        {steps.map((step, index) => (
          <li key={index} className="mb-4">
            <h3 className="font-semibold mb-2">Step {index + 1}</h3>
            {index === 0 && (
              <div className="mb-4">
                <div className="relative" style={{ paddingTop: "56.25%" }}>
                  <video
                    className="absolute top-0 left-0 w-full h-full rounded-lg"
                    controls
                  >
                    <source src={video} type="video/mp4" />
                    Your browser does not support the video tag.
                  </video>
                </div>
                <div className="mt-2">
                  <ul className="list-disc pl-6">
                    <li>
                      In a mixing bowl, combine all-purpose flour and salt.
                    </li>
                    <li>Gradually add water and knead to form a soft dough.</li>
                    <li>
                      Cover the dough with a damp cloth and let it rest for 30
                      minutes.
                    </li>
                  </ul>
                </div>
              </div>
            )}
            <p>{step}</p>
          </li>
        ))}
      </ol>

      <h2 className="text-xl font-semibold mb-4">Ingredients</h2>
      <div className="flex justify-between mb-6">
        {ingredients.slice(0, 3).map((ingredient, index) => (
          <div
            key={index}
            className="bg-white rounded-lg p-3 shadow text-center flex-1 mx-2"
          >
            <h3 className="font-semibold mb-2">Main Ingredients</h3>
            <p>{ingredient}</p>
            {index === 0 && <p>2 cups</p>}
            {index === 1 && <p>1/2 teaspoon</p>}
            {index === 2 && <p>as needed</p>}
          </div>
        ))}
      </div>
    </div>
  );
}

/*
next step

<div className="flex justify-between items-center">
        <button className="bg-gray-200 text-gray-700 px-4 py-2 rounded">
          First Step
        </button>
        <span>1 of 6</span>
        <button className="bg-blue-500 text-white px-4 py-2 rounded">
          Next Step
        </button>
      </div>




ai-search
<div className="w-full mt-8 relative">
          <div className="flex items-center">
            <input
              type="text"
              placeholder="Ask something..."
              className="flex-grow p-2 rounded-lg border border-gray-300 focus:outline-none focus:border-gray-500"
            />
            <FaMicrophone className="absolute right-16 top-3 text-gray-400" />{" "}
            <div className="bg-blue-200 rounded-full p-2 ml-2">
              <FaRobot className="text-2xl text-blue-500" /> 
              </div>
              </div>
            </div>
*/
