import "./style.css";
import { useState } from "react";
import { darkColors, lightColors } from "./data/homeTheme";
import Navbar from "./components/Navbar";
import SideBar from "./components/Sidebar";
import MainContent from "./MainContent.jsx";

const SecondaryIntelligence = () => {
  const [lightMode, setLightMode] = useState(true);
  const colors = lightMode ? lightColors : darkColors;
  const [sideBarOpen, setSideBarOpen] = useState(false);

  return (
    <>
      <Navbar
        lightMode={lightMode}
        setLightMode={setLightMode}
        sideBarOpen={sideBarOpen}
        setSideBarOpen={setSideBarOpen}
      />
      <div className={`${colors.backgroundOfBody} ${colors.text}`}>
        <div className="relative flex flex-grow">
          {sideBarOpen && <SideBar lightMode={lightMode} />}
          {/* main content */}
          <div className="flex-grow">
            <MainContent />
          </div>
        </div>
      </div>
    </>
  );
};

export default SecondaryIntelligence;
