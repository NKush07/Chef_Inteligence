import React, { useState } from "react";

const MainContent = () => {
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState("");
  const [hideSuggestion, setHideSuggestion] = useState(false);

  const suggestions = [
    { title: "Chiken Briyani", subtitle: "yummy chunks of chiken rice" },
    {
      title: "Masala Dosa",
      subtitle: "smashed potato with dosa",
    },
    {
      title: "Upma",
      subtitle: "a heavy breakfast",
    },
    { title: "Special Sauce", subtitle: "a sauce to use in all veggies" },
  ];

  const handleSendMessage = async (e) => {
    e.preventDefault();
    setHideSuggestion(true);
    if (inputMessage.trim()) {
      setMessages([...messages, { text: inputMessage, sender: "user" }]);
      setInputMessage("");

      try {
        const response = await fetch("http://localhost:5000/generate_recipe", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ dish: inputMessage }),
        });
        const data = await response.json();

        if (data.error) {
          throw new Error(data.error);
        }

        // Format the recipe data into a readable message
        const formattedRecipe = `
  Recipe for ${data.dish_name}:
  
  Ingredients:
  ${data.ingredients}
  
  Steps:
  ${data.steps.map((step, index) => `${index + 1}. ${step}`).join("\n")}
        `.trim();

        setMessages((prev) => [
          ...prev,
          {
            text: formattedRecipe,
            sender: "AI Chef",
            videoUrl: data.video_link, // Store the video URL separately
          },
        ]);
      } catch (error) {
        console.error("Error:", error);
        setMessages((prev) => [
          ...prev,
          {
            text: `Sorry, I couldn't find a recipe for that dish. ${error.message}`,
            sender: "AI Chef",
          },
        ]);
      }
    }
  };

  return (
    <div className="flex flex-col items-center pt-5 pb-4 px-4 min-h-screen">
      {/* Chat Area */}
      {hideSuggestion ? (
        <div className="w-full max-w-3xl h-[33rem] bg-gray-800 rounded-lg mb-4 p-4 overflow-y-auto">
          {messages.map((message, index) => (
            <div
              key={index}
              className={`mb-4 ${
                message.sender === "user" ? "text-right" : "text-left"
              }`}
            >
              <span
                className={`inline-block p-2 rounded-lg ${
                  message.sender === "user"
                    ? "bg-blue-500 text-white"
                    : "bg-gray-700 text-white"
                }`}
              >
                <pre className="whitespace-pre-wrap font-sans text-sm">
                  {message.text}
                </pre>
              </span>
              {message.videoUrl && (
                <div className="mt-2">
                  <iframe
                    width="100%"
                    height="315"
                    src={message.videoUrl}
                    title="Recipe Video"
                    frameBorder="0"
                    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                  ></iframe>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="w-full max-w-3xl bg-gray-800 rounded-lg mb-4 p-4 h-80 overflow-y-auto">
          {messages.map((message, index) => (
            <div
              key={index}
              className={`mb-2 ${
                message.sender === "user" ? "text-right" : "text-left"
              }`}
            >
              <span
                className={`inline-block p-2 rounded-lg ${
                  message.sender === "user"
                    ? "bg-blue-500 text-white"
                    : "bg-gray-700 text-white"
                }`}
              >
                {message.text}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Suggestion Boxes */}
      {hideSuggestion ? (
        <></>
      ) : (
        <div className="grid grid-cols-2 gap-4 mb-8 w-full max-w-3xl">
          {suggestions.map((item, index) => (
            <div
              key={index}
              className="bg-gray-800 p-4 rounded-lg cursor-pointer hover:bg-gray-700 transition-colors"
            >
              <h2 className="text-lg font-semibold text-white">{item.title}</h2>
              <p className="text-sm text-gray-400">{item.subtitle}</p>
            </div>
          ))}
        </div>
      )}

      {/* Message Input */}
      <form onSubmit={handleSendMessage} className="w-full max-w-3xl relative">
        <input
          type="text"
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          placeholder="Message AiChief"
          className="w-full bg-gray-700 text-white rounded-md py-3 px-4 pr-10 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          type="submit"
          className="absolute right-3 top-1/2 transform -translate-y-1/2"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="h-5 w-5 text-gray-400"
            viewBox="0 0 20 20"
            fill="currentColor"
          >
            <path
              fillRule="evenodd"
              d="M5.293 7.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 5.414V17a1 1 0 11-2 0V5.414L6.707 7.707a1 1 0 01-1.414 0z"
              clipRule="evenodd"
            />
          </svg>
        </button>
      </form>
    </div>
  );
};

export default MainContent;
