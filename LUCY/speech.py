import speech_recognition as sr
import pyttsx3
import time

class Speech:
    def __init__(self, voice_name="Samantha", rate=180):
        self.r = sr.Recognizer()
        self.voice_name = voice_name
        self.rate = rate

    def _new_engine(self):
        engine = pyttsx3.init()
        engine.setProperty('rate', self.rate)
        for v in engine.getProperty("voices"):
            if self.voice_name.lower() in getattr(v, "name", ""):
                engine.setProperty('voice', v.id)
                break
        return engine

    def capture(self):
        with sr.Microphone() as source:
            self.r.adjust_for_ambient_noise(source, duration=0.4)
            audio = self.r.listen(source)
        try:
            return self.r.recognize_google(audio)
        except:
            return ""

    def speak(self, response):
        try:
            engine = self._new_engine()
            engine.say(response)
            engine.runAndWait()
            try:
                engine.stop()
            except:
                pass
        except Exception as e:
            print(f"Error: {e}")
